//! PureNT Clean-Room Window Management Subsystem
//! Window frame rendering, non-client area calculation, and Z-order dispatch matching Windows 7 SP1 Aero

use super::surface::{Rect, Surface};

pub const BORDER_LEFT: u32 = 10;
pub const BORDER_RIGHT: u32 = 10;
pub const BORDER_BOTTOM: u32 = 10;
pub const CAPTION_HEIGHT: u32 = 32;

const CAPTION_BUTTONS_WIDTH: u32 = 104;
const CAPTION_BUTTONS_HEIGHT: u32 = 21;
const CAPTION_BUTTONS_INSET: i32 = 8;
const CLOSE_BUTTON_WIDTH: u32 = 48;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaptionHit {
    Outside,
    Caption,
    Buttons,
    Close,
}

static CAPSULE_104X21: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/capsule_104x21.raw"));
static CMD_ICON_16X16: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/cmd_icon_16x16.raw"));

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
            self.rect.x + BORDER_LEFT as i32,
            self.rect.y + CAPTION_HEIGHT as i32,
            self.rect.width.saturating_sub(BORDER_LEFT + BORDER_RIGHT),
            self.rect.height.saturating_sub(CAPTION_HEIGHT + BORDER_BOTTOM),
        )
    }

    fn caption_buttons(&self) -> Rect {
        Rect::new(
            self.rect.right() - CAPTION_BUTTONS_INSET - CAPTION_BUTTONS_WIDTH as i32,
            self.rect.y + 1,
            CAPTION_BUTTONS_WIDTH,
            CAPTION_BUTTONS_HEIGHT,
        )
    }

    pub fn hit_test_caption(&self, x: i32, y: i32) -> CaptionHit {
        let buttons = self.caption_buttons();
        if buttons.contains(x, y) {
            if x >= buttons.right() - CLOSE_BUTTON_WIDTH as i32 {
                CaptionHit::Close
            } else {
                CaptionHit::Buttons
            }
        } else if !self.is_minimized
            && Rect::new(self.rect.x, self.rect.y, self.rect.width, CAPTION_HEIGHT).contains(x, y)
        {
            CaptionHit::Caption
        } else {
            CaptionHit::Outside
        }
    }

    pub fn draw_glass(&self, surface: &mut Surface, redirected: bool) {
        let rect = self.rect;
        let client = self.client_rect();
        let color = if redirected { purent_ntdef::composition::GLASS_PIXEL } else { 0xFFA0B2BF };
        for strip in [
            Rect::new(rect.x, rect.y, rect.width, CAPTION_HEIGHT),
            Rect::new(rect.x, client.y, BORDER_LEFT, client.height),
            Rect::new(client.right(), client.y, BORDER_RIGHT, client.height),
            Rect::new(rect.x, client.bottom(), rect.width, BORDER_BOTTOM),
        ] {
            surface.fill_rect(strip, color);
        }
    }

    pub fn draw_frame(&self, surface: &mut Surface) {
        if self.is_minimized {
            return;
        }

        let rx = self.rect.x;
        let ry = self.rect.y;
        surface.draw_rect(self.rect, 0xFF667988);
        surface.fill_rect(Rect::new(rx + 1, ry + 1, self.rect.width - 2, 1), 0xFFE4EDF2);
        let client = self.client_rect();
        surface.draw_rect(
            Rect::new(client.x - 1, client.y - 1, client.width + 2, client.height + 2),
            0xFF778894,
        );

        let buttons = self.caption_buttons();
        surface.blit_raw_rgba(buttons.x, buttons.y, buttons.width, buttons.height, CAPSULE_104X21);

        // 8. Authentic 16x16 Command Prompt [C:\] Application Icon
        let icon_x = rx + 10;
        let icon_y = ry + 8;
        surface.blit_raw_rgba(icon_x, icon_y, 16, 16, CMD_ICON_16X16);

        // 9. Optional Title Text with White Diffuse Halo (if non-empty)
        if !self.title.is_empty() {
            let text_x = rx + 32;
            let text_y = ry + 8;
            for &dx in &[-1, 1, 0] {
                for &dy in &[-1, 1, 0] {
                    if dx != 0 || dy != 0 {
                        surface.draw_text(text_x + dx, text_y + dy, self.title, 0xFFDCE7ED, None);
                    }
                }
            }
            surface.draw_text(text_x, text_y, self.title, 0xFF172932, None);
        }
    }
}
