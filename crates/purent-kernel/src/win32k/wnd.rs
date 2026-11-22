//! PureNT Clean-Room Window Management Subsystem
//! Window frame rendering, non-client area calculation, and Z-order dispatch matching Windows 7 SP1

use super::surface::{CaptionButtonType, Rect, Surface};

pub const BORDER_WIDTH: u32 = 4;
pub const CAPTION_HEIGHT: u32 = 28;

pub struct Window {
    pub hwnd: usize,
    pub title: &'static str,
    pub rect: Rect,
    pub is_active: bool,
    pub is_minimized: bool,
    pub is_maximized: bool,
}

impl Window {
    pub const fn new(hwnd: usize, title: &'static str, rect: Rect) -> Self {
        Self {
            hwnd,
            title,
            rect,
            is_active: true,
            is_minimized: false,
            is_maximized: false,
        }
    }

    pub fn client_rect(&self) -> Rect {
        Rect::new(
            self.rect.x + BORDER_WIDTH as i32,
            self.rect.y + CAPTION_HEIGHT as i32 + BORDER_WIDTH as i32,
            self.rect.width.saturating_sub(BORDER_WIDTH * 2),
            self.rect.height.saturating_sub(CAPTION_HEIGHT + BORDER_WIDTH * 2),
        )
    }

    /// Renders the complete Windows 7 Non-Client Window Frame (borders, caption, buttons)
    pub fn draw_frame(&self, surface: &mut Surface) {
        if self.is_minimized {
            return;
        }

        // 1. Outer Borders (4px width)
        let border_color = if self.is_active {
            0xFF1B3A57 // Active Aero slate-blue border
        } else {
            0xFF4A5560 // Inactive border
        };
        surface.draw_rect(self.rect, border_color);
        surface.draw_rect(
            Rect::new(self.rect.x + 1, self.rect.y + 1, self.rect.width - 2, self.rect.height - 2),
            border_color,
        );

        // 2. Caption Bar (Horizontal gradient)
        let caption_rect = Rect::new(
            self.rect.x + BORDER_WIDTH as i32,
            self.rect.y + BORDER_WIDTH as i32,
            self.rect.width.saturating_sub(BORDER_WIDTH * 2),
            CAPTION_HEIGHT,
        );

        let (grad_start, grad_end) = if self.is_active {
            (0xFF0F3B66, 0xFF2A68A5) // Windows 7 Active Titlebar Gradient
        } else {
            (0xFF4A5A6A, 0xFF6C7C8C) // Inactive Titlebar Gradient
        };
        surface.draw_gradient_h(caption_rect, grad_start, grad_end);

        // Highlight line at top of caption
        surface.fill_rect(
            Rect::new(caption_rect.x, caption_rect.y, caption_rect.width, 1),
            0xFF5B8FC4,
        );

        // 3. Window Icon / Title Text
        let text_x = caption_rect.x + 10;
        let text_y = caption_rect.y + 6;
        // Text drop shadow (1px offset)
        surface.draw_text(text_x + 1, text_y + 1, self.title, 0xFF000000, None);
        // Text foreground
        surface.draw_text(text_x, text_y, self.title, 0xFFFFFFFF, None);

        // 4. Caption Buttons (Minimize [_], Maximize [□], Close [X])
        let btn_w = 26;
        let btn_h = 18;
        let btn_y = caption_rect.y + 4;
        let mut btn_x = caption_rect.right() - (btn_w as i32) - 4;

        // Close button
        surface.draw_caption_button(
            Rect::new(btn_x, btn_y, btn_w, btn_h),
            CaptionButtonType::Close,
            true,
        );

        // Maximize button
        btn_x -= (btn_w as i32) + 2;
        surface.draw_caption_button(
            Rect::new(btn_x, btn_y, btn_w, btn_h),
            CaptionButtonType::Maximize,
            false,
        );

        // Minimize button
        btn_x -= (btn_w as i32) + 2;
        surface.draw_caption_button(
            Rect::new(btn_x, btn_y, btn_w, btn_h),
            CaptionButtonType::Minimize,
            false,
        );

        // 5. Client Area border separator
        let client = self.client_rect();
        surface.draw_rect(
            Rect::new(client.x - 1, client.y - 1, client.width + 2, client.height + 2),
            0xFF1B2836,
        );
    }
}
