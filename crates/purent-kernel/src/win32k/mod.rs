//! PureNT Clean-Room Windows 7 Window Manager & Graphical Subsystem (win32k)
//! Reverse-engineered matching Windows 7 SP1 x64 win32k.sys and user32.dll

pub mod console;
pub mod desktop;
pub mod font;
pub mod surface;
pub mod wnd;

use console::ConsoleWindow;
use desktop::Desktop;
use purent_hal::kprintln;
use purent_hal::sync::SpinLock;
use purent_ntdef::loader::FramebufferInfo;
use surface::Surface;

pub struct Win32kSubsystem {
    pub desktop: Desktop,
    pub console: ConsoleWindow,
    pub hw_surface: Surface,
    pub initialized: bool,
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

    let mut hw_surface = unsafe {
        Surface::from_raw(
            fb.base_address as *mut u32,
            fb.width,
            fb.height,
            fb.pixels_per_scan_line,
        )
    };

    let desktop = Desktop::new(fb.width, fb.height);

    // Center the 648x420 console window on the 1280x800 display (accounting for 36px taskbar)
    let console_w = 648;
    let console_h = 420;
    let win_x = ((fb.width as i32) - console_w) / 2;
    let win_y = ((fb.height as i32) - 36 - console_h) / 2;
    let mut console = ConsoleWindow::new(win_x.max(10), win_y.max(10));

    // Initial banner inside the cmd console window
    console.write_str("Microsoft Windows [Version 6.1.7601]\r\n");
    console.write_str("Copyright (c) 2009 Microsoft Corporation.  All rights reserved.\r\n\r\n");
    console.write_str("C:\\Windows\\system32>");

    // 1. Draw Windows 7 Desktop wallpaper & taskbar
    desktop.draw_background(&mut hw_surface);

    // 2. Draw active cmd.exe window with caption gradient and Marlett glyph buttons
    console.draw(&mut hw_surface);

    // 3. Draw standard Aero mouse cursor
    desktop.draw_cursor(&mut hw_surface);

    *WIN32K.lock() = Some(Win32kSubsystem {
        desktop,
        console,
        hw_surface,
        initialized: true,
    });

    kprintln!("[WIN32K] Windows 7 Desktop & Window Manager active.");
}

pub fn win32k_console_write(text: &str) {
    let mut guard = WIN32K.lock();
    if let Some(ref mut win32k) = *guard {
        win32k.console.write_str(text);
        win32k.console.draw(&mut win32k.hw_surface);
        win32k.desktop.draw_cursor(&mut win32k.hw_surface);
    }
}

pub fn win32k_render_frame() {
    let mut guard = WIN32K.lock();
    if let Some(ref mut win32k) = *guard {
        win32k.desktop.draw_background(&mut win32k.hw_surface);
        win32k.console.draw(&mut win32k.hw_surface);
        win32k.desktop.draw_cursor(&mut win32k.hw_surface);
    }
}
