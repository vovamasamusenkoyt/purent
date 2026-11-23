//! PureNT Clean-Room Windows 7 Window Manager & Graphical Subsystem (win32k)
//! Reverse-engineered matching Windows 7 SP1 x64 win32k.sys and user32.dll

mod dialog;
pub(crate) mod windows;
pub(crate) mod compositor;
pub mod console;
pub mod desktop;
pub mod font;
pub mod input;
pub mod surface;
pub mod wnd;
mod ui_font;

use crate::mm::pool::ExFreePool;
use console::ConsoleWindow;
use desktop::Desktop;
use purent_hal::{kprintln, Ps2Input};
use purent_hal::sync::SpinLock;
use purent_ntdef::{composition::MAX_WINDOW_SURFACES, dialog::DialogText};
use purent_ntdef::loader::FramebufferInfo;
use surface::{Rect, Surface};
use wnd::CaptionHit;

pub const CONSOLE_CLIENT_PID: usize = 0x300;
pub const CONHOST_PID: usize = 0x500;
pub const DWM_PID: usize = 0x600;
pub const WINDOWDEMO_PID: usize = 0x700;

pub struct Win32kSubsystem {
    pub desktop: Desktop,
    pub console: ConsoleWindow,
    hw_surface: Surface,
    frame: Surface,
    windows: [Option<windows::DesktopWindow>; MAX_WINDOW_SURFACES],
    message_queues: [windows::MessageQueue; MAX_WINDOW_SURFACES],
    next_hwnd: usize,
    damage: Option<Rect>,
    focused_window: Option<usize>,
    compositor: Option<compositor::Compositor>,
    pub initialized: bool,
}

impl Win32kSubsystem {
    fn present(&mut self, region: Rect) {
        // The composed frame is in kernel RAM, separate from GOP memory.
        unsafe { self.hw_surface.copy_region(&self.frame, region) };
    }

    fn screen(&self) -> Rect {
        Rect::new(0, 0, self.frame.width, self.frame.height)
    }

    fn compose_region(&mut self, region: Rect) -> bool {
        let screen = self.screen();
        let Some(compositor) = self.compositor.as_mut() else {
            return false;
        };
        let window = &self.console.window;
        let console = (!window.is_minimized).then_some((window.rect, window.client_rect()));
        compositor.compose(screen, region, console, &self.windows);
        true
    }

    fn invalidate(&mut self, rect: Rect) {
        self.damage = Some(self.damage.map_or(rect, |damage| damage.union(rect)));
    }

    fn window_index(&self, owner: usize) -> Option<usize> {
        self.windows.iter().position(|window| window.as_ref().is_some_and(|window| window.id == owner))
    }

    fn set_focus(&mut self, owner: Option<usize>) {
        if self.focused_window == owner {
            return;
        }
        let previous = core::mem::replace(&mut self.focused_window, owner);
        if let Some(previous) = previous {
            self.post_window_message(previous, purent_ntdef::window::WM_KILLFOCUS, owner.unwrap_or(0));
        }
        if let Some(owner) = owner {
            self.post_window_message(owner, purent_ntdef::window::WM_SETFOCUS, previous.unwrap_or(0));
        }
        if self.console.window.is_active != owner.is_none() {
            self.console.window.is_active = owner.is_none();
            if !self.console.window.is_minimized {
                if let Some(compositor) = self.compositor.as_mut() {
                    self.console.draw(&mut compositor.console, true);
                }
                self.invalidate(self.console.window.rect);
            }
        }
        for owner in [previous, owner].into_iter().flatten() {
            if let Some(index) = self.window_index(owner) {
                let window = self.windows[index].as_ref().expect("window at index");
                if let Some(compositor) = self.compositor.as_mut() {
                    compositor.draw_window(window, self.focused_window == Some(owner));
                }
                self.invalidate(window.rect);
            }
        }
    }

    fn raise_window(&mut self, index: usize) {
        let window = self.windows[index].as_ref().expect("window at index");
        let owner = window.id;
        let rect = window.rect;
        self.set_focus(Some(owner));
        let top = self.windows.iter().flatten().count() - 1;
        if index != top {
            let window = self.windows[index].take();
            for slot in index..top {
                self.windows[slot] = self.windows[slot + 1].take();
            }
            self.windows[top] = window;
            self.invalidate(rect);
        }
    }

    fn render_frame(&mut self) {
        let screen = self.screen();
        if let Some(compositor) = self.compositor.as_mut() {
            self.console.draw(&mut compositor.console, true);
            for window in self.windows.iter().flatten() {
                compositor.draw_window(window, self.focused_window == Some(window.id));
            }
        }
        if !self.compose_region(screen) {
            self.desktop.draw_background(&mut self.frame);
            self.console.draw(&mut self.frame, false);
            for window in self.windows.iter().flatten() {
                window.draw(&mut self.frame, window.rect, false, self.focused_window == Some(window.id));
            }
        }
        self.desktop.draw_cursor(&mut self.frame);
        self.present(screen);
    }

    fn redraw(&mut self, pointer: Option<(i32, i32)>) {
        let damage = self.damage.take();
        if damage.is_none() && pointer.is_none() {
            return;
        }

        let old_cursor = self.desktop.cursor_rect();
        self.desktop.erase_cursor(&mut self.frame);
        if let Some((x, y)) = pointer {
            self.desktop.mouse_x = x;
            self.desktop.mouse_y = y;
        }
        if let Some(region) = damage {
            if !self.compose_region(region) {
                self.render_frame();
                return;
            }
        }
        self.desktop.draw_cursor(&mut self.frame);
        if let Some(region) = damage {
            self.present(region);
        }
        if pointer.is_some() {
            self.present(old_cursor);
            self.present(self.desktop.cursor_rect());
        }
    }

}

static WIN32K: SpinLock<Option<Win32kSubsystem>> = SpinLock::new(None);

pub fn win32k_init(fb: &FramebufferInfo) {
    if fb.base_address == 0 || fb.width == 0 || fb.height == 0 {
        kprintln!("[WIN32K] Framebuffer not present; skipping GUI initialization.");
        return;
    }

    kprintln!(
        "[WIN32K] Initializing Windows 7 Desktop Subsystem: {}x{} @ {} bpp (base 0x{:016X}, stride {})",
        fb.width,
        fb.height,
        32,
        fb.base_address,
        fb.pixels_per_scan_line
    );

    let Some(frame_bytes) = (fb.width as usize)
        .checked_mul(fb.height as usize)
        .and_then(|pixels| pixels.checked_mul(core::mem::size_of::<u32>()))
    else {
        kprintln!("[WIN32K] Frame dimensions exceed addressable memory.");
        return;
    };
    if frame_bytes > isize::MAX as usize || fb.pixels_per_scan_line < fb.width {
        kprintln!("[WIN32K] Invalid framebuffer dimensions.");
        return;
    }
    let Some((pixels, allocation)) = (unsafe { compositor::allocate_page_aligned(frame_bytes) }) else {
        kprintln!("[WIN32K] Could not allocate a composition buffer.");
        return;
    };
    let frame = unsafe { Surface::from_raw(pixels.cast(), fb.width, fb.height, fb.width) };

    let hw_surface = unsafe {
        Surface::from_raw(
            fb.base_address as *mut u32,
            fb.width,
            fb.height,
            fb.pixels_per_scan_line,
        )
    };

    let desktop = Desktop::new(fb.width, fb.height);

    // Center the authentic 565x347 console window on the display
    let console_w = 565;
    let console_h = 347;
    let win_x = ((fb.width as i32) - console_w) / 2;
    let win_y = ((fb.height as i32) - console_h) / 2;
    let Some(console) = ConsoleWindow::new(win_x.max(10), win_y.max(10)) else {
        unsafe { ExFreePool(allocation) };
        kprintln!("[WIN32K] Could not allocate the console surface.");
        return;
    };

    let mut subsystem = Win32kSubsystem {
        desktop,
        console,
        hw_surface,
        frame,
        windows: [const { None }; MAX_WINDOW_SURFACES],
        message_queues: [const { windows::MessageQueue::EMPTY }; MAX_WINDOW_SURFACES],
        next_hwnd: windows::HWND_BASE,
        damage: None,
        focused_window: None,
        compositor: None,
        initialized: true,
    };
    subsystem.render_frame();

    *WIN32K.lock() = Some(subsystem);

    kprintln!("[WIN32K] Windows 7 Desktop, Aero Window Manager & PS/2 Mouse active.");
}

pub fn prepare_compositor() -> bool {
    let mut guard = WIN32K.lock();
    let Some(subsystem) = guard.as_mut() else { return false };
    match unsafe { compositor::Compositor::prepare(&subsystem.frame, subsystem.console.window.rect) } {
        Ok(compositor) => {
            subsystem.compositor = Some(compositor);
            true
        }
        Err(status) => {
            kprintln!("[WIN32K] Compositor surfaces unavailable: 0x{:08X}", status);
            false
        }
    }
}

pub fn activate_compositor() {
    if let Some(subsystem) = WIN32K.lock().as_mut() {
        subsystem.render_frame();
        kprintln!("[WIN32K] Initial frame composed by user-mode dwm.exe");
    }
}

pub fn console_client_write(bytes: &[u8]) {
    for &byte in bytes {
        while !input::CONSOLE_OUTPUT.push(byte) {
            unsafe { purent_hal::cpu::halt() };
        }
    }
}

pub fn win32k_console_write(text: &str) {
    if let Some(subsystem) = WIN32K.lock().as_mut() {
        subsystem.console.write_str(text);
        update_console_text(subsystem);
    }
}

pub fn win32k_reset_console() {
    if let Some(subsystem) = WIN32K.lock().as_mut() {
        subsystem.console.clear();
        update_console_text(subsystem);
    }
}

fn update_console_text(subsystem: &mut Win32kSubsystem) {
    if subsystem.console.window.is_minimized {
        return;
    }
    if let Some(compositor) = &mut subsystem.compositor {
        subsystem.console.draw_redirected_text(&mut compositor.console);
    }
    subsystem.invalidate(subsystem.console.text_rect());
}

pub fn win32k_render_frame() {
    let mut guard = WIN32K.lock();
    if let Some(ref mut win32k) = *guard {
        win32k.render_frame();
    }
}

pub unsafe fn show_dialog(address: usize) -> purent_ntdef::status::NtStatus {
    use crate::mm::{vmm_query_user_page, PTE_HUGE, PTE_USER};
    use purent_ntdef::status::{STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    let Some(last) = address.checked_add(core::mem::size_of::<DialogText>() - 1) else {
        return STATUS_INVALID_PARAMETER;
    };
    if address == 0 || last >= 0x0000_8000_0000_0000 {
        return STATUS_INVALID_PARAMETER;
    }
    let cr3 = purent_hal::cpu::read_cr3();
    let first_page = address & !4095;
    let last_page = last & !4095;
    for page in (first_page..=last_page).step_by(4096) {
        if vmm_query_user_page(cr3, page as u64)
            .is_none_or(|(_, flags)| flags & (PTE_USER | PTE_HUGE) != PTE_USER)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    let Some(owner) = crate::ps::current_process_id() else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    let text = core::ptr::read(address as *const DialogText);
    {
        let mut guard = WIN32K.lock();
        let Some(subsystem) = guard.as_mut() else {
            return STATUS_INVALID_DEVICE_REQUEST;
        };
        let Some((position, slot)) = subsystem.free_window_slot() else {
            return STATUS_INVALID_DEVICE_REQUEST;
        };
        let rect = dialog::initial_bounds(subsystem.frame.width, subsystem.frame.height, slot);
        let window = windows::DesktopWindow {
            id: owner, slot, rect, content: windows::WindowContent::Modal(text),
        };
        subsystem.windows[position] = Some(window);
        subsystem.set_focus(Some(owner));
    }
    kprintln!("[WIN32K] USER32 requested a modal dialog (PID: 0x{:X})", owner);
    loop {
        let pending = WIN32K.lock().as_ref().is_some_and(|subsystem| {
            subsystem.windows.iter().flatten().any(|dialog| dialog.id == owner)
        });
        if !pending {
            return STATUS_SUCCESS;
        }
        purent_hal::cpu::halt();
    }
}

impl Win32kSubsystem {
    fn top_window(&self) -> Option<usize> {
        self.windows.iter().rev().flatten().find(|window| window.visible()).map(|window| window.id)
    }

    fn remove_window(&mut self, hwnd: usize) {
        let Some(index) = self.window_index(hwnd) else { return };
        let window = self.windows[index].take().expect("window index");
        if window.visible() {
            self.invalidate(window.rect);
        }
        for slot in index..self.windows.len() - 1 {
            self.windows[slot] = self.windows[slot + 1].take();
        }
        let last = self.windows.len() - 1;
        self.windows[last] = None;
        if self.focused_window == Some(hwnd) {
            self.set_focus(self.top_window());
        }
    }
}

fn dismiss_dialog(subsystem: &mut Win32kSubsystem, owner: usize) {
    subsystem.remove_window(owner);
    kprintln!("[WIN32K] Dismissed modal dialog (PID: 0x{:X})", owner);
}

#[derive(Clone, Copy)]
enum PointerCapture {
    None,
    DragConsole { offset_x: i32, offset_y: i32 },
    CloseConsole,
    DragWindow { owner: usize, offset_x: i32, offset_y: i32 },
    CloseWindow { owner: usize, caption: bool },
}

fn capture_pointer(subsystem: &mut Win32kSubsystem, x: i32, y: i32) -> PointerCapture {
    if let Some(index) = subsystem.windows.iter().rposition(|window| {
        window.as_ref().is_some_and(|window| window.visible() && window.rect.contains(x, y))
    }) {
        let window = subsystem.windows[index].as_ref().expect("window at index");
        let (owner, rect, modal) = (window.id, window.rect, window.is_modal());
        subsystem.raise_window(index);
        let caption = dialog::close_button(rect).contains(x, y);
        if caption || (modal && dialog::ok_button(rect).contains(x, y)) {
            return PointerCapture::CloseWindow { owner, caption };
        }
        if dialog::caption(rect).contains(x, y) {
            return PointerCapture::DragWindow { owner, offset_x: x - rect.x, offset_y: y - rect.y };
        }
        return PointerCapture::None;
    }

    let window = subsystem.console.window;
    if !window.is_minimized && window.rect.contains(x, y) {
        subsystem.set_focus(None);
    }
    match window.hit_test_caption(x, y) {
        CaptionHit::Caption => PointerCapture::DragConsole {
            offset_x: x - window.rect.x,
            offset_y: y - window.rect.y,
        },
        CaptionHit::Close => PointerCapture::CloseConsole,
        CaptionHit::Outside | CaptionHit::Buttons => PointerCapture::None,
    }
}

fn drag_pointer(subsystem: &mut Win32kSubsystem, capture: PointerCapture, x: i32, y: i32) {
    let width = subsystem.frame.width;
    let height = subsystem.frame.height;
    let (rect, new_x, new_y) = match capture {
        PointerCapture::DragConsole { offset_x, offset_y } => {
            (&mut subsystem.console.window.rect, x - offset_x, y - offset_y)
        }
        PointerCapture::DragWindow { owner, offset_x, offset_y } => {
            let Some(index) = subsystem.window_index(owner) else { return };
            let rect = &mut subsystem.windows[index].as_mut().expect("window at index").rect;
            let new_x = (x - offset_x).clamp(0, width.saturating_sub(rect.width) as i32);
            let new_y = (y - offset_y).clamp(0, height.saturating_sub(rect.height) as i32);
            (rect, new_x, new_y)
        }
        _ => return,
    };

    if (rect.x, rect.y) != (new_x, new_y) {
        let previous = *rect;
        rect.x = new_x;
        rect.y = new_y;
        let damage = previous.union(*rect);
        subsystem.invalidate(damage);
    }
}

fn release_pointer(subsystem: &mut Win32kSubsystem, capture: PointerCapture, x: i32, y: i32) {
    match capture {
        PointerCapture::CloseConsole
            if subsystem.console.window.hit_test_caption(x, y) == CaptionHit::Close =>
        {
            let window = &mut subsystem.console.window;
            window.is_minimized = !window.is_minimized;
            let rect = window.rect;
            if let Some(compositor) = &mut subsystem.compositor {
                subsystem.console.draw(&mut compositor.console, true);
            }
            subsystem.invalidate(rect);
        }
        PointerCapture::CloseWindow { owner, caption } => {
            let Some(index) = subsystem.window_index(owner) else { return };
            let rect = subsystem.windows[index].as_ref().expect("window at index").rect;
            let button = if caption { dialog::close_button(rect) } else { dialog::ok_button(rect) };
            if button.contains(x, y) {
                subsystem.request_close(owner);
            }
        }
        _ => {}
    }
}

pub unsafe fn win32k_run_event_loop(mut cmd_thread: *mut purent_ntdef::kpcr::KThread) -> ! {
    let mut keyboard = input::Keyboard::default();
    let mut capture = PointerCapture::None;
    let mut left_was_down = false;

    loop {
        crate::ps::builtin::service();
        if !cmd_thread.is_null() && core::ptr::read_volatile(&raw const (*cmd_thread).header[4]) != 0 {
            crate::ps::ps_reap_thread(cmd_thread);
            cmd_thread = core::ptr::null_mut();
        }

        match purent_hal::ps2_poll_input() {
            Some(Ps2Input::Keyboard(scan)) => {
                let Some(ch) = keyboard.decode(scan) else { continue };
                if let Some(subsystem) = WIN32K.lock().as_mut() {
                    if ch == b'\t' && subsystem.top_window().is_some() {
                        let owner = if subsystem.focused_window.is_some() {
                            None
                        } else {
                            subsystem.top_window()
                        };
                        subsystem.set_focus(owner);
                    } else if let Some(owner) = subsystem.focused_window {
                        if matches!(ch, 13 | 27) && subsystem.window_index(owner).is_some_and(|index| {
                            subsystem.windows[index].as_ref().is_some_and(windows::DesktopWindow::is_modal)
                        }) {
                            dismiss_dialog(subsystem, owner);
                        }
                    } else if !matches!(ch, 9 | 27) {
                        input::KEYBOARD_INPUT.push(ch);
                    }
                }
            }
            Some(Ps2Input::Mouse(event)) => {
                if let Some(subsystem) = WIN32K.lock().as_mut() {
                    let desktop = &subsystem.desktop;
                    let x = (desktop.mouse_x + event.dx).clamp(0, desktop.width as i32 - 1);
                    let y = (desktop.mouse_y - event.dy).clamp(0, desktop.height as i32 - 1);
                    let moved = (x, y) != (desktop.mouse_x, desktop.mouse_y);
                    match (left_was_down, event.left_button) {
                        (false, true) => capture = capture_pointer(subsystem, x, y),
                        (true, true) => drag_pointer(subsystem, capture, x, y),
                        (true, false) => {
                            drag_pointer(subsystem, capture, x, y);
                            release_pointer(subsystem, capture, x, y);
                            capture = PointerCapture::None;
                        }
                        _ => {}
                    }
                    left_was_down = event.left_button;
                    subsystem.redraw(moved.then_some((x, y)));
                }
            }
            Some(Ps2Input::PartialMousePacket) => {}
            None => {
                if let Some(subsystem) = WIN32K.lock().as_mut() {
                    subsystem.redraw(None);
                }
                purent_hal::cpu::halt();
            }
        }
    }
}
