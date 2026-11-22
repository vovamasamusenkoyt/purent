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

    // Center the authentic 565x347 console window on the display
    let console_w = 565;
    let console_h = 347;
    let win_x = ((fb.width as i32) - console_w) / 2;
    let win_y = ((fb.height as i32) - console_h) / 2;
    let mut console = ConsoleWindow::new(win_x.max(10), win_y.max(10));

    // Authentic Windows 7 Command Prompt text stream matching reference screenshot
    console.write_str("Microsoft Windows [Version 6.1.7601]\r\n");
    console.write_str("Copyright (c) 2009 Microsoft Corporation.  All rights reserved.\r\n\r\n");
    console.write_str("C:\\Windows\\system32>cd c:\\\r\n\r\n");
    console.write_str("c:\\>PsExec.exe -i -s cmd.exe\r\n\r\n");
    console.write_str("PsExec v1.98 - Execute processes remotely\r\n");
    console.write_str("Copyright (C) 2001-2010 Mark Russinovich\r\n");
    console.write_str("Sysinternals - www.sysinternals.com\r\n\r\n");

    // 1. Draw Windows 7 Desktop wallpaper
    desktop.draw_background(&mut hw_surface);

    // 2. Draw active cmd.exe window with caption gradient and Marlett glyph buttons
    console.draw(&mut hw_surface);

    // 3. Draw standard Aero mouse cursor
    desktop.draw_cursor(&mut hw_surface);

    // 4. Initialize PS/2 mouse hardware driver
    unsafe {
        purent_hal::ps2_mouse_init();
    }

    *WIN32K.lock() = Some(Win32kSubsystem {
        desktop,
        console,
        hw_surface,
        initialized: true,
    });

    kprintln!("[WIN32K] Windows 7 Desktop, Aero Window Manager & PS/2 Mouse active.");
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

/// Interactive Windows 7 Desktop & Window Manager event loop
/// Dispatches PS/2 mouse motion, button clicks, and window dragging in real-time
pub fn win32k_run_event_loop() -> ! {
    let mut dragging = false;
    let mut drag_offset_x = 0;
    let mut drag_offset_y = 0;

    loop {
        let mouse_event = unsafe { purent_hal::ps2_mouse_poll() };
        if let Some(event) = mouse_event {
            let mut guard = WIN32K.lock();
            if let Some(subsystem) = guard.as_mut() {
                let prev_x = subsystem.desktop.mouse_x;
                let prev_y = subsystem.desktop.mouse_y;

                // Update cursor coordinates (clamped to screen dimensions)
                let new_x = (prev_x + event.dx).clamp(0, subsystem.desktop.width as i32 - 1);
                // PS/2 mouse dY is positive upwards, so subtract dY for downward screen coordinates
                let new_y = (prev_y - event.dy).clamp(0, subsystem.desktop.height as i32 - 1);

                subsystem.desktop.mouse_x = new_x;
                subsystem.desktop.mouse_y = new_y;

                let win_rect = subsystem.console.window.rect;

                if event.left_button {
                    if !dragging {
                        // Title bar hit test: y in rect.y..rect.y + 32
                        if new_x >= win_rect.x
                            && new_x < win_rect.right()
                            && new_y >= win_rect.y
                            && new_y < win_rect.y + 32
                        {
                            // Close button hit test (x in rx + 453 + 56..rx + 453 + 104, y in ry + 1..ry + 22)
                            let close_x = win_rect.x + 453 + 56;
                            let close_y = win_rect.y + 1;
                            if new_x >= close_x && new_x < close_x + 48 && new_y >= close_y && new_y < close_y + 21 {
                                // Close button clicked: toggle minimize
                                subsystem.console.window.is_minimized = !subsystem.console.window.is_minimized;
                            } else {
                                // Start dragging window
                                dragging = true;
                                drag_offset_x = new_x - win_rect.x;
                                drag_offset_y = new_y - win_rect.y;
                            }
                        }
                    } else {
                        // Dragging in progress: update window rect
                        let new_win_x = new_x - drag_offset_x;
                        let new_win_y = new_y - drag_offset_y;
                        subsystem.console.window.rect.x = new_win_x;
                        subsystem.console.window.rect.y = new_win_y;
                    }
                } else {
                    dragging = false;
                }

                // If mouse position changed or window was dragged, redraw scene
                if new_x != prev_x || new_y != prev_y || dragging {
                    subsystem.desktop.draw_background(&mut subsystem.hw_surface);
                    subsystem.console.draw(&mut subsystem.hw_surface);
                    subsystem.desktop.draw_cursor(&mut subsystem.hw_surface);
                }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}
