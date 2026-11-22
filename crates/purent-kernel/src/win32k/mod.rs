//! PureNT Clean-Room Windows 7 Window Manager & Graphical Subsystem (win32k)
//! Reverse-engineered matching Windows 7 SP1 x64 win32k.sys and user32.dll

mod dialog;
pub(crate) mod compositor;
pub mod console;
pub mod desktop;
pub mod font;
pub mod input;
pub mod surface;
pub mod wnd;

use crate::mm::pool::ExFreePool;
use console::ConsoleWindow;
use desktop::Desktop;
use purent_hal::{kprintln, Ps2Input};
use purent_hal::sync::SpinLock;
use purent_ntdef::dialog::DialogText;
use purent_ntdef::loader::FramebufferInfo;
use surface::{Rect, Surface};
use wnd::CaptionHit;

pub const CONSOLE_CLIENT_PID: usize = 0x300;
pub const CONHOST_PID: usize = 0x500;
pub const DWM_PID: usize = 0x600;

pub struct Win32kSubsystem {
    pub desktop: Desktop,
    pub console: ConsoleWindow,
    hw_surface: Surface,
    frame: Surface,
    dialog_text: Option<DialogText>,
    compositor: Option<compositor::Compositor>,
    pub initialized: bool,
}

impl Win32kSubsystem {
    fn present(&mut self, region: Rect) {
        // The composed frame is in kernel RAM, separate from GOP memory.
        unsafe { self.hw_surface.copy_region(&self.frame, region) };
    }

    fn compose_region(&mut self, region: Rect) -> bool {
        let Some(compositor) = self.compositor.as_mut() else {
            return false;
        };
        let console = (!self.console.window.is_minimized).then_some(self.console.window.rect);
        let dialog = self.dialog_text.as_ref()
            .filter(|_| dialog::visible())
            .map(|_| dialog::bounds(self.frame.width, self.frame.height));
        compositor.compose(region, console, self.console.window.client_rect(), dialog);
        true
    }

    fn render_frame(&mut self) {
        let screen = Rect::new(0, 0, self.frame.width, self.frame.height);
        if let Some(compositor) = self.compositor.as_mut() {
            self.console.draw(&mut compositor.console, true);
            if let Some(text) = self.dialog_text.as_ref().filter(|_| dialog::visible()) {
                dialog::draw(&mut compositor.dialog, text);
            }
        }
        if !self.compose_region(screen) {
            self.desktop.draw_background(&mut self.frame);
            self.console.draw(&mut self.frame, false);
            if let Some(text) = self.dialog_text.as_ref().filter(|_| dialog::visible()) {
                dialog::draw(&mut self.frame, text);
            }
        }
        self.desktop.draw_cursor(&mut self.frame);
        self.present(screen);
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
        dialog_text: None,
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
    match unsafe { compositor::Compositor::prepare(&subsystem.frame) } {
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
    let mut guard = WIN32K.lock();
    if let Some(ref mut win32k) = *guard {
        win32k.console.write_str(text);
        if !win32k.console.window.is_minimized && !dialog::visible() {
            win32k.desktop.erase_cursor(&mut win32k.frame);
            let text_rect = win32k.console.text_rect();
            if let Some(compositor) = &mut win32k.compositor {
                win32k.console.draw_text_surface(&mut compositor.console);
                win32k.compose_region(text_rect);
            } else {
                win32k.console.draw_text_surface(&mut win32k.frame);
            }
            win32k.desktop.draw_cursor(&mut win32k.frame);
            win32k.present(text_rect);
        }
    }
}

pub fn win32k_reset_console() {
    if let Some(win32k) = WIN32K.lock().as_mut() {
        win32k.console.clear();
        win32k.render_frame();
    }
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

    let text = core::ptr::read(address as *const DialogText);
    {
        let mut guard = WIN32K.lock();
        let Some(subsystem) = guard.as_mut() else {
            return STATUS_INVALID_DEVICE_REQUEST;
        };
        if !dialog::request() {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        subsystem.dialog_text = Some(text);
    }
    kprintln!("[WIN32K] USER32 requested a modal dialog");
    while dialog::pending() {
        purent_hal::cpu::halt();
    }
    dialog::finish();
    STATUS_SUCCESS
}

fn dismiss_dialog(subsystem: &mut Win32kSubsystem) {
    subsystem.dialog_text = None;
    dialog::dismiss();
    if let Some(compositor) = &mut subsystem.compositor {
        let dialog_rect = dialog::bounds(subsystem.frame.width, subsystem.frame.height);
        let region = if subsystem.console.window.is_minimized {
            dialog_rect
        } else {
            subsystem.console.draw_text_surface(&mut compositor.console);
            dialog_rect.union(subsystem.console.window.rect)
        };
        subsystem.desktop.erase_cursor(&mut subsystem.frame);
        subsystem.compose_region(region);
        subsystem.desktop.draw_cursor(&mut subsystem.frame);
        subsystem.present(region);
    } else {
        subsystem.render_frame();
    }
}

enum CaptionCapture {
    None,
    Drag { offset_x: i32, offset_y: i32 },
    Close,
}

/// Interactive Windows 7 Desktop & Window Manager event loop
/// Dispatches PS/2 mouse motion, button clicks, and window dragging in real-time
pub unsafe fn win32k_run_event_loop(
    cmd_thread: *mut purent_ntdef::kpcr::KThread,
    winver_thread: *mut purent_ntdef::kpcr::KThread,
) -> ! {
    let mut threads = [cmd_thread, winver_thread];
    let mut dialog_pressed = false;
    let mut keyboard = input::Keyboard::default();
    let mut capture = CaptionCapture::None;
    let mut left_was_down = false;

    loop {
        for thread in &mut threads {
            if !thread.is_null() && core::ptr::read_volatile(&raw const (**thread).header[4]) != 0 {
                crate::ps::ps_reap_thread(*thread);
                *thread = core::ptr::null_mut();
            }
        }
        if dialog::open_requested() {
            if let Some(subsystem) = WIN32K.lock().as_mut() {
                subsystem.desktop.erase_cursor(&mut subsystem.frame);
                let region = dialog::bounds(subsystem.frame.width, subsystem.frame.height);
                if let Some(text) = &subsystem.dialog_text {
                    if let Some(compositor) = &mut subsystem.compositor {
                        dialog::draw(&mut compositor.dialog, text);
                        subsystem.compose_region(region);
                    } else {
                        dialog::draw(&mut subsystem.frame, text);
                    }
                }
                subsystem.desktop.draw_cursor(&mut subsystem.frame);
                subsystem.present(region);
            }
            capture = CaptionCapture::None;
        }

        let event = match purent_hal::ps2_poll_input() {
            Some(Ps2Input::Keyboard(scan)) => {
                if let Some(ch) = keyboard.decode(scan) {
                    if dialog::visible() {
                        if matches!(ch, 13 | 27) {
                            if let Some(subsystem) = WIN32K.lock().as_mut() {
                                dismiss_dialog(subsystem);
                            }
                            dialog_pressed = false;
                        }
                    } else if ch != 27 {
                        input::KEYBOARD_INPUT.push(ch);
                    }
                }
                continue;
            }
            Some(Ps2Input::Mouse(event)) => event,
            Some(Ps2Input::PartialMousePacket) => continue,
            None => {
                purent_hal::cpu::halt();
                continue;
            }
        };
        {
            let mut guard = WIN32K.lock();
            if let Some(subsystem) = guard.as_mut() {
                let prev_x = subsystem.desktop.mouse_x;
                let prev_y = subsystem.desktop.mouse_y;

                // Update cursor coordinates (clamped to screen dimensions)
                let new_x = (prev_x + event.dx).clamp(0, subsystem.desktop.width as i32 - 1);
                // PS/2 mouse dY is positive upwards, so subtract dY for downward screen coordinates
                let new_y = (prev_y - event.dy).clamp(0, subsystem.desktop.height as i32 - 1);

                if dialog::visible() {
                    let button = dialog::ok_button(dialog::bounds(subsystem.frame.width, subsystem.frame.height));
                    let over_button = button.contains(new_x, new_y);
                    if event.left_button && !left_was_down {
                        dialog_pressed = over_button;
                    }
                    let dismiss = !event.left_button && left_was_down && dialog_pressed && over_button;
                    left_was_down = event.left_button;

                    let old_cursor = subsystem.desktop.cursor_rect();
                    if dismiss {
                        dialog_pressed = false;
                        dismiss_dialog(subsystem);
                    }
                    subsystem.desktop.erase_cursor(&mut subsystem.frame);
                    subsystem.desktop.mouse_x = new_x;
                    subsystem.desktop.mouse_y = new_y;
                    subsystem.desktop.draw_cursor(&mut subsystem.frame);
                    subsystem.present(old_cursor);
                    subsystem.present(subsystem.desktop.cursor_rect());
                    continue;
                }

                let window = &mut subsystem.console.window;
                let win_rect = window.rect;
                let was_minimized = window.is_minimized;
                let hit = window.hit_test_caption(new_x, new_y);

                if event.left_button && !left_was_down {
                    capture = match hit {
                        CaptionHit::Caption => CaptionCapture::Drag {
                            offset_x: new_x - win_rect.x,
                            offset_y: new_y - win_rect.y,
                        },
                        CaptionHit::Close => CaptionCapture::Close,
                        CaptionHit::Buttons | CaptionHit::Outside => CaptionCapture::None,
                    };
                } else if event.left_button {
                    if let CaptionCapture::Drag { offset_x, offset_y } = capture {
                        window.rect.x = new_x - offset_x;
                        window.rect.y = new_y - offset_y;
                    }
                } else if left_was_down {
                    if matches!(capture, CaptionCapture::Close) && hit == CaptionHit::Close {
                        window.is_minimized = !window.is_minimized;
                    }
                    capture = CaptionCapture::None;
                }
                left_was_down = event.left_button;

                let new_rect = window.rect;
                let is_minimized = window.is_minimized;
                let window_changed = was_minimized != is_minimized
                    || (!is_minimized && new_rect != win_rect);
                if window_changed && subsystem.compositor.is_some() {
                    let old_cursor = subsystem.desktop.cursor_rect();
                    subsystem.desktop.erase_cursor(&mut subsystem.frame);
                    let region = match (was_minimized, is_minimized) {
                        (true, false) => new_rect,
                        (false, true) => win_rect,
                        _ => win_rect.union(new_rect),
                    };
                    if let Some(compositor) = &mut subsystem.compositor {
                        subsystem.console.draw(&mut compositor.console, true);
                    }
                    subsystem.compose_region(region);
                    subsystem.desktop.mouse_x = new_x;
                    subsystem.desktop.mouse_y = new_y;
                    subsystem.desktop.draw_cursor(&mut subsystem.frame);
                    subsystem.present(region);
                    subsystem.present(old_cursor);
                    subsystem.present(subsystem.desktop.cursor_rect());
                    continue;
                }
                if new_x != prev_x || new_y != prev_y || window_changed {
                    let desktop = &mut subsystem.desktop;
                    let surface = &mut subsystem.frame;
                    let old_cursor = desktop.cursor_rect();
                    desktop.erase_cursor(surface);
                    if window_changed {
                        if !was_minimized {
                            let visible_rect = (!is_minimized).then_some(new_rect);
                            desktop.restore_exposed_background(surface, win_rect, visible_rect);
                        }
                        subsystem.console.draw(surface, false);
                    }
                    desktop.mouse_x = new_x;
                    desktop.mouse_y = new_y;
                    desktop.draw_cursor(surface);
                    let new_cursor = desktop.cursor_rect();
                    if window_changed {
                        if !was_minimized {
                            subsystem.present(win_rect);
                        }
                        if !is_minimized && (was_minimized || new_rect != win_rect) {
                            subsystem.present(new_rect);
                        }
                    }
                    subsystem.present(old_cursor);
                    subsystem.present(new_cursor);
                }
            }
        }
    }
}
