//! PureNT Clean-Room Desktop & Taskbar (Shell_TrayWnd)
//! Renders the classic Windows 7 Desktop environment and system taskbar

use super::surface::{Rect, Surface};

pub const TASKBAR_HEIGHT: u32 = 36;

pub struct Desktop {
    pub width: u32,
    pub height: u32,
    pub mouse_x: i32,
    pub mouse_y: i32,
}

impl Desktop {
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            mouse_x: 640,
            mouse_y: 400,
        }
    }

    /// Renders the Windows 7 Desktop wallpaper and bottom Taskbar
    pub fn draw_background(&self, surface: &mut Surface) {
        // 1. Desktop Wallpaper (Windows 7 Azure Blue Vertical Gradient)
        let desk_rect = Rect::new(0, 0, self.width, self.height.saturating_sub(TASKBAR_HEIGHT));
        surface.draw_gradient_v(desk_rect, 0xFF0E3860, 0xFF1D5A92);

        // Subtle ambient center highlight
        let center_x = (self.width as i32) / 2;
        let center_y = (desk_rect.height as i32) / 2;
        surface.draw_gradient_h(
            Rect::new(center_x - 300, center_y - 150, 600, 300),
            0xFF184976,
            0xFF236CAE,
        );

        // 2. Taskbar (Bottom 36px)
        let taskbar_rect = Rect::new(0, self.height as i32 - TASKBAR_HEIGHT as i32, self.width, TASKBAR_HEIGHT);
        // Slate Glass Vertical Gradient
        surface.draw_gradient_v(taskbar_rect, 0xFF1E2B38, 0xFF0D151F);

        // Top highlight border
        surface.fill_rect(
            Rect::new(taskbar_rect.x, taskbar_rect.y, taskbar_rect.width, 1),
            0xFF4A657E,
        );

        // 3. Start Button on the left
        let start_rect = Rect::new(4, taskbar_rect.y + 3, 76, TASKBAR_HEIGHT - 6);
        surface.draw_gradient_v(start_rect, 0xFF2A4D72, 0xFF142B44);
        surface.draw_rect(start_rect, 0xFF43709E);
        // Start text with Windows symbol
        surface.draw_text(start_rect.x + 8, start_rect.y + 8, "Start", 0xFFFFFFFF, None);

        // 4. Active Taskbar Pill for cmd.exe
        let pill_rect = Rect::new(88, taskbar_rect.y + 3, 200, TASKBAR_HEIGHT - 6);
        // Active pressed look
        surface.draw_gradient_v(pill_rect, 0xFF183858, 0xFF0B1F33);
        surface.draw_rect(pill_rect, 0xFF356595);
        // Bottom active glow indicator
        surface.fill_rect(
            Rect::new(pill_rect.x + 2, pill_rect.bottom() - 2, pill_rect.width - 4, 2),
            0xFF00A2ED,
        );
        surface.draw_text(pill_rect.x + 10, pill_rect.y + 8, ">_ cmd.exe", 0xFFFFFFFF, None);

        // 5. System Tray & Clock on the right
        let clock_rect = Rect::new(self.width as i32 - 70, taskbar_rect.y + 3, 66, TASKBAR_HEIGHT - 6);
        surface.draw_text(clock_rect.x + 12, clock_rect.y + 8, "22:00", 0xFFD8E4EE, None);

        // Desktop corner peak strip (Windows 7 Aero Peek button on far right)
        surface.fill_rect(
            Rect::new(self.width as i32 - 12, taskbar_rect.y, 12, TASKBAR_HEIGHT),
            0xFF243648,
        );
        surface.draw_rect(
            Rect::new(self.width as i32 - 12, taskbar_rect.y, 12, TASKBAR_HEIGHT),
            0xFF4B6986,
        );
    }

    /// Renders mouse cursor at current coordinates
    pub fn draw_cursor(&self, surface: &mut Surface) {
        surface.draw_cursor(self.mouse_x, self.mouse_y);
    }
}
