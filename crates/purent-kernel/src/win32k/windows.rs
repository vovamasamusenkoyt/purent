use purent_ntdef::{dialog::DialogText, status::*, window as abi};

use super::{
    dialog,
    wnd::{FrameControls, NonClient},
    Rect, Surface, Win32kSubsystem, WIN32K,
};

pub const MAX_WIDTH: u32 = 520;
pub const MAX_HEIGHT: u32 = 320;
pub(super) const HWND_BASE: usize = 0x4000_0000;
const QUEUE_SIZE: usize = 32;

pub struct DesktopWindow {
    pub id: usize,
    pub slot: usize,
    pub rect: Rect,
    pub content: WindowContent,
}

pub enum WindowContent {
    Modal(DialogText),
    Application(AppWindow),
}

pub struct AppWindow {
    process: usize,
    thread: usize,
    title: [u8; 64],
    visible: bool,
    invalid: Option<Rect>,
    painting: Option<Rect>,
    erase: bool,
}

impl DesktopWindow {
    pub fn visible(&self) -> bool {
        match &self.content {
            WindowContent::Modal(_) => true,
            WindowContent::Application(app) => app.visible,
        }
    }

    pub fn is_modal(&self) -> bool {
        matches!(self.content, WindowContent::Modal(_))
    }

    pub fn draw(&self, surface: &mut Surface, rect: Rect, redirected: bool, active: bool) {
        match &self.content {
            WindowContent::Modal(text) => dialog::draw(surface, rect, text, redirected, active),
            WindowContent::Application(app) => {
                let len = app
                    .title
                    .iter()
                    .position(|&ch| ch == 0)
                    .unwrap_or(app.title.len());
                let title = core::str::from_utf8(&app.title[..len]).unwrap_or("");
                NonClient {
                    frame: rect,
                    client: dialog::client(rect),
                    controls: FrameControls::Close,
                }
                .draw(surface, title, 13, redirected, active);
            }
        }
    }
}

pub struct MessageQueue {
    process: usize,
    thread: usize,
    messages: [abi::Message; QUEUE_SIZE],
    head: usize,
    len: usize,
    quit: Option<i32>,
}

impl MessageQueue {
    pub const EMPTY: Self = Self {
        process: 0,
        thread: 0,
        head: 0,
        len: 0,
        quit: None,
        messages: [abi::Message {
            hwnd: 0,
            message: 0,
            wparam: 0,
            lparam: 0,
            time: 0,
            x: 0,
            y: 0,
            private: 0,
        }; QUEUE_SIZE],
    };

    fn push(&mut self, message: abi::Message) {
        if message.message == abi::WM_CLOSE {
            let queued =
                (0..self.len).map(|offset| self.messages[(self.head + offset) % QUEUE_SIZE]);
            if queued
                .into_iter()
                .any(|other| other.hwnd == message.hwnd && other.message == abi::WM_CLOSE)
            {
                return;
            }
        }
        if self.len == QUEUE_SIZE {
            if message.message != abi::WM_CLOSE {
                return;
            }
            // Preserve pending close requests when focus changes fill the queue.
            let Some(offset) = (0..self.len).find(|offset| {
                self.messages[(self.head + offset) % QUEUE_SIZE].message != abi::WM_CLOSE
            }) else {
                return;
            };
            for offset in offset..self.len - 1 {
                self.messages[(self.head + offset) % QUEUE_SIZE] =
                    self.messages[(self.head + offset + 1) % QUEUE_SIZE];
            }
            self.len -= 1;
        }
        self.messages[(self.head + self.len) % QUEUE_SIZE] = message;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<abi::Message> {
        if self.len == 0 {
            return None;
        }
        let message = self.messages[self.head];
        self.head = (self.head + 1) % QUEUE_SIZE;
        self.len -= 1;
        Some(message)
    }

    fn remove_window(&mut self, hwnd: usize) {
        let len = self.len;
        for _ in 0..len {
            if let Some(message) = self.pop().filter(|message| message.hwnd != hwnd) {
                self.push(message);
            }
        }
    }
}

fn make_message(hwnd: usize, message: u32, wparam: usize) -> abi::Message {
    let ticks = unsafe { core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS) };
    abi::Message {
        hwnd,
        message,
        wparam,
        time: ticks.wrapping_mul(10) as u32,
        ..abi::Message::default()
    }
}

impl Win32kSubsystem {
    pub(super) fn free_window_slot(&self) -> Option<(usize, usize)> {
        let index = self.windows.iter().position(Option::is_none)?;
        let slot = (0..self.windows.len()).find(|slot| {
            self.windows
                .iter()
                .flatten()
                .all(|window| window.slot != *slot)
        })?;
        Some((index, slot))
    }

    fn queue(&mut self, process: usize, thread: usize) -> Option<&mut MessageQueue> {
        let index = self
            .message_queues
            .iter()
            .position(|queue| queue.thread == thread)
            .or_else(|| {
                self.message_queues
                    .iter()
                    .position(|queue| queue.thread == 0)
            })?;
        let queue = &mut self.message_queues[index];
        queue.process = process;
        queue.thread = thread;
        Some(queue)
    }

    pub(super) fn post_window_message(&mut self, hwnd: usize, message: u32, wparam: usize) {
        let Some(index) = self.window_index(hwnd) else {
            return;
        };
        let Some(DesktopWindow {
            content: WindowContent::Application(app),
            ..
        }) = self.windows[index].as_ref()
        else {
            return;
        };
        if let Some(queue) = self.queue(app.process, app.thread) {
            queue.push(make_message(hwnd, message, wparam));
        }
    }

    pub(super) fn request_close(&mut self, hwnd: usize) {
        let Some(index) = self.window_index(hwnd) else {
            return;
        };
        if self.windows[index]
            .as_ref()
            .is_some_and(DesktopWindow::is_modal)
        {
            super::dismiss_dialog(self, hwnd);
        } else {
            self.post_window_message(hwnd, abi::WM_CLOSE, 0);
        }
    }

    fn app_index(&self, hwnd: usize, process: usize, thread: usize) -> Option<usize> {
        let index = self.window_index(hwnd)?;
        match &self.windows[index].as_ref()?.content {
            WindowContent::Application(app) if app.process == process && app.thread == thread => {
                Some(index)
            }
            _ => None,
        }
    }

    fn next_message(
        &mut self,
        process: usize,
        thread: usize,
    ) -> Result<Option<abi::Message>, NtStatus> {
        let queue = self.queue(process, thread).ok_or(STATUS_NO_MEMORY)?;
        if let Some(message) = queue.pop() {
            return Ok(Some(message));
        }
        if let Some(code) = queue.quit.take() {
            return Ok(Some(make_message(0, abi::WM_QUIT, code as usize)));
        }
        for window in self.windows.iter().flatten() {
            if let WindowContent::Application(app) = &window.content {
                if app.thread == thread
                    && app.visible
                    && app.invalid.is_some()
                    && app.painting.is_none()
                {
                    return Ok(Some(make_message(window.id, abi::WM_PAINT, 0)));
                }
            }
        }
        Ok(None)
    }

    fn create_window(
        &mut self,
        process: usize,
        thread: usize,
        mut req: abi::WindowCreate,
    ) -> NtStatus {
        let Some((index, slot)) = self.free_window_slot() else {
            return STATUS_NO_MEMORY;
        };
        if self.compositor.is_none() {
            return STATUS_NOT_SUPPORTED;
        }
        if req.width == i32::MIN {
            req.width = 360;
        }
        if req.height == i32::MIN {
            req.height = 230;
        }
        if !(120..=MAX_WIDTH as i32).contains(&req.width)
            || !(90..=MAX_HEIGHT as i32).contains(&req.height)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if self.queue(process, thread).is_none() || self.next_hwnd >= i32::MAX as usize {
            return STATUS_NO_MEMORY;
        }
        let x_limit = self.frame.width.saturating_sub(req.width as u32) as i32;
        let y_limit = self.frame.height.saturating_sub(req.height as u32) as i32;
        let default = 24 + slot as i32 * 36;
        let x = if req.x == i32::MIN { default } else { req.x }.clamp(0, x_limit);
        let y = if req.y == i32::MIN { default } else { req.y }.clamp(0, y_limit);
        let hwnd = self.next_hwnd;
        self.next_hwnd += 1;
        let mut title = [0; 64];
        for (out, unit) in title
            .iter_mut()
            .zip(req.title)
            .take_while(|(_, unit)| *unit != 0)
        {
            *out = u8::try_from(unit).ok().filter(u8::is_ascii).unwrap_or(b'?');
        }
        let rect = Rect::new(x, y, req.width as u32, req.height as u32);
        let local = Rect::new(0, 0, rect.width, rect.height);
        let client = dialog::client(local);
        let window = DesktopWindow {
            id: hwnd,
            slot,
            rect,
            content: WindowContent::Application(AppWindow {
                process,
                thread,
                title,
                visible: false,
                invalid: Some(Rect::new(0, 0, client.width, client.height)),
                painting: None,
                erase: false,
            }),
        };
        let compositor = self.compositor.as_mut().expect("window surface");
        compositor.windows[slot].fill_rect(local, 0xFFF7F8FB);
        compositor.draw_window(&window, false);
        self.windows[index] = Some(window);
        hwnd as NtStatus
    }
}

fn clip_to_client(input: abi::Rect, client: Rect) -> Rect {
    let left = input.left.clamp(0, client.width as i32);
    let top = input.top.clamp(0, client.height as i32);
    let right = input.right.clamp(left, client.width as i32);
    let bottom = input.bottom.clamp(top, client.height as i32);
    Rect::new(left, top, (right - left) as u32, (bottom - top) as u32)
}

unsafe fn user_buffer<T>(address: usize, write: bool) -> Option<*mut T> {
    use crate::mm::{vmm_query_user_page, PTE_HUGE, PTE_USER, PTE_WRITABLE};
    let last = address.checked_add(core::mem::size_of::<T>() - 1)?;
    if address == 0 || last >= 0x0000_8000_0000_0000 {
        return None;
    }
    let flags = PTE_USER | if write { PTE_WRITABLE } else { 0 };
    let cr3 = purent_hal::cpu::read_cr3();
    for page in ((address & !4095)..=(last & !4095)).step_by(4096) {
        if vmm_query_user_page(cr3, page as u64)
            .is_none_or(|(_, pte)| pte & (flags | PTE_HUGE) != flags)
        {
            return None;
        }
    }
    Some(address as *mut T)
}

pub unsafe fn service(operation: u64, hwnd: usize, arg: usize, extra: usize) -> NtStatus {
    let thread = purent_hal::cpu::read_gs_u64(0x188) as usize;
    let Some(process) = crate::ps::current_process_id() else {
        return STATUS_ACCESS_DENIED;
    };
    if operation == abi::GET_MESSAGE {
        let Some(out) = user_buffer::<abi::Message>(arg, true) else {
            return STATUS_INVALID_PARAMETER;
        };
        loop {
            let message = {
                let mut desktop = WIN32K.lock();
                let Some(desktop) = desktop.as_mut() else {
                    return STATUS_NOT_SUPPORTED;
                };
                desktop.next_message(process, thread)
            };
            match message {
                Ok(Some(message)) => {
                    out.write_unaligned(message);
                    return i32::from(message.message != abi::WM_QUIT);
                }
                Err(status) => return status,
                Ok(None) => purent_hal::cpu::halt(),
            }
        }
    }

    let mut guard = WIN32K.lock();
    let Some(desktop) = guard.as_mut() else {
        return STATUS_NOT_SUPPORTED;
    };
    if operation == abi::CREATE {
        let Some(req) = user_buffer::<abi::WindowCreate>(arg, false) else {
            return STATUS_INVALID_PARAMETER;
        };
        return desktop.create_window(process, thread, req.read_unaligned());
    }
    if operation == abi::POST_QUIT {
        let Some(queue) = desktop.queue(process, thread) else {
            return STATUS_NO_MEMORY;
        };
        queue.quit = Some(arg as i32);
        return STATUS_SUCCESS;
    }
    let Some(index) = desktop.app_index(hwnd, process, thread) else {
        return STATUS_INVALID_HANDLE;
    };
    if operation == abi::DESTROY {
        desktop.remove_window(hwnd);
        if let Some(queue) = desktop.queue(process, thread) {
            queue.remove_window(hwnd);
        }
        return STATUS_SUCCESS;
    }
    let window = desktop.windows[index].as_mut().expect("window index");
    let WindowContent::Application(app) = &mut window.content else {
        return STATUS_INVALID_HANDLE;
    };
    let rect = window.rect;
    let client = dialog::client(Rect::new(0, 0, rect.width, rect.height));
    match operation {
        abi::SHOW => {
            let previous = app.visible;
            app.visible = arg != 0;
            let visible = app.visible;
            desktop.invalidate(rect);
            if visible && !previous {
                desktop.raise_window(index);
            } else if !visible && desktop.focused_window == Some(hwnd) {
                desktop.set_focus(desktop.top_window());
            }
            i32::from(previous)
        }
        abi::INVALIDATE => {
            let damage = if arg == 0 {
                Rect::new(0, 0, client.width, client.height)
            } else {
                let Some(input) = user_buffer::<abi::Rect>(arg, false) else {
                    return STATUS_INVALID_PARAMETER;
                };
                clip_to_client(input.read_unaligned(), client)
            };
            if damage.width > 0 && damage.height > 0 {
                app.invalid = Some(
                    app.invalid
                        .map_or(damage, |previous| previous.union(damage)),
                );
                app.erase |= extra != 0;
            }
            STATUS_SUCCESS
        }
        abi::BEGIN_PAINT => {
            let Some(out) = user_buffer::<abi::PaintStruct>(arg, true) else {
                return STATUS_INVALID_PARAMETER;
            };
            if app.painting.is_some() {
                return STATUS_INVALID_PARAMETER;
            }
            let damage = app.invalid.take().unwrap_or_default();
            app.painting = Some(damage);
            // Report the erase request to the caller for this paint pass.
            let erase = core::mem::take(&mut app.erase);
            out.write_unaligned(abi::PaintStruct {
                dc: hwnd,
                erase: i32::from(erase),
                paint: abi::Rect {
                    left: damage.x,
                    top: damage.y,
                    right: damage.right(),
                    bottom: damage.bottom(),
                },
                restore: 0,
                inc_update: 0,
                reserved: [0; 32],
            });
            STATUS_SUCCESS
        }
        abi::END_PAINT => {
            let Some(damage) = app.painting.take() else {
                return STATUS_INVALID_PARAMETER;
            };
            if app.visible && damage.width > 0 && damage.height > 0 {
                let target = dialog::client(rect);
                desktop.invalidate(Rect::new(
                    target.x + damage.x,
                    target.y + damage.y,
                    damage.width,
                    damage.height,
                ));
            }
            STATUS_SUCCESS
        }
        abi::FILL_RECT => {
            let Some(damage) = app.painting else {
                return STATUS_INVALID_PARAMETER;
            };
            let Some(input) = user_buffer::<abi::Rect>(arg, false) else {
                return STATUS_INVALID_PARAMETER;
            };
            if let Some(fill) = clip_to_client(input.read_unaligned(), client).intersect(&damage) {
                let fill = Rect::new(
                    client.x + fill.x,
                    client.y + fill.y,
                    fill.width,
                    fill.height,
                );
                let compositor = desktop.compositor.as_mut().expect("window surface");
                compositor.windows[window.slot]
                    .fill_rect(fill, 0xFF00_0000 | extra as u32 & 0x00FF_FFFF);
            }
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

pub fn remove_process(process: usize) {
    let mut guard = WIN32K.lock();
    let Some(desktop) = guard.as_mut() else {
        return;
    };
    while let Some(hwnd) =
        desktop
            .windows
            .iter()
            .flatten()
            .find_map(|window| match &window.content {
                WindowContent::Application(app) if app.process == process => Some(window.id),
                _ => None,
            })
    {
        desktop.remove_window(hwnd);
    }
    for queue in &mut desktop.message_queues {
        if queue.process == process {
            *queue = MessageQueue::EMPTY;
        }
    }
}
