//! PureNT Clean-Room Window Management Subsystem
//! Window frame rendering, non-client area calculation, and Z-order dispatch matching Windows 7 SP1 Aero

use super::surface::{Rect, Surface};

pub const BORDER_LEFT: u32 = 10;
pub const BORDER_RIGHT: u32 = 10;
pub const BORDER_BOTTOM: u32 = 10;
pub const CAPTION_HEIGHT: u32 = 32;

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

    /// Renders the authentic Windows 7 Aero Glass Window Frame matching DWM composition
    pub fn draw_frame(&self, surface: &mut Surface) {
        if self.is_minimized {
            return;
        }

        let rx = self.rect.x;
        let ry = self.rect.y;
        let rw = self.rect.width as i32;
        let rh = self.rect.height as i32;
        let right = rx + rw;
        let bottom = ry + rh;

        // 1. Frosted Translucent Aero Glass Titlebar (0..32px)
        for y_rel in 0..CAPTION_HEIGHT as i32 {
            let py = ry + y_rel;
            let color = if y_rel == 0 {
                0xFF323232 // Outer 1px frame line
            } else if y_rel == 1 {
                0xFFFEFEFE // Crisp 1px highlight line
            } else if y_rel == 30 {
                0xFFFCFCFC
            } else if y_rel == 31 {
                0xFF797979 // Inner client separator line
            } else {
                0xFFFBFBFB // Pure frosted glass
            };

            for px in rx..right {
                surface.put_pixel(px, py, color);
            }
        }

        // 2. Left Aero Glass Border (10px wide)
        for x_rel in 0..BORDER_LEFT as i32 {
            let lx = rx + x_rel;
            let color = if x_rel == 0 {
                0xFF323232 // Outer 1px frame line
            } else if x_rel == 1 {
                0xFFFFFFFF // Highlight line
            } else if x_rel == 9 {
                0xFF797979 // Inner client separator line
            } else {
                0xFFFDFDFD // Frosted glass border fill
            };

            for py in (ry + CAPTION_HEIGHT as i32)..bottom {
                surface.put_pixel(lx, py, color);
            }
        }

        // 3. Right Aero Glass Border (10px wide: x = right - 10..right)
        for x_rel in 0..BORDER_RIGHT as i32 {
            let rrx = right - BORDER_RIGHT as i32 + x_rel;
            let color = if x_rel == 0 {
                0xFF797979 // Inner client separator line
            } else if x_rel == 8 {
                0xFFFFFFFF // Highlight line
            } else if x_rel == 9 {
                0xFF323232 // Outer 1px frame line
            } else {
                0xFFFDFDFD // Frosted glass border fill
            };

            for py in (ry + CAPTION_HEIGHT as i32)..bottom {
                surface.put_pixel(rrx, py, color);
            }
        }

        // 4. Bottom Aero Glass Border (10px tall: y = bottom - 10..bottom)
        for y_rel in 0..BORDER_BOTTOM as i32 {
            let py = bottom - BORDER_BOTTOM as i32 + y_rel;
            let color = if y_rel == 0 {
                0xFF797979 // Inner client separator line
            } else if y_rel == 1 {
                0xFFFCFCFC
            } else if y_rel == 8 {
                0xFFFEFEFE // Highlight line
            } else if y_rel == 9 {
                0xFF323232 // Outer 1px frame line
            } else {
                0xFFFBFBFB // Frosted glass base fill
            };

            for px in rx..right {
                surface.put_pixel(px, py, color);
            }
        }

        // 5. Smooth Rounded Top Corners (Radius 8px)
        let top_radius = 8;
        for j in 0..top_radius {
            for i in 0..top_radius {
                let dist_sq = (top_radius - 1 - i) * (top_radius - 1 - i) + (top_radius - 1 - j) * (top_radius - 1 - j);
                if dist_sq > (top_radius * top_radius - top_radius * 2) {
                    surface.put_pixel(rx + i, ry + j, 0xFF323232);
                    surface.put_pixel(right - 1 - i, ry + j, 0xFF323232);
                }
            }
        }

        // 6. Smooth Rounded Bottom Corners (Radius 6px)
        let bot_radius = 6;
        for j in 0..bot_radius {
            for i in 0..bot_radius {
                let dist_sq = (bot_radius - 1 - i) * (bot_radius - 1 - i) + (bot_radius - 1 - j) * (bot_radius - 1 - j);
                if dist_sq > (bot_radius * bot_radius - bot_radius * 2) {
                    surface.put_pixel(rx + i, bottom - 1 - j, 0xFF323232);
                    surface.put_pixel(right - 1 - i, bottom - 1 - j, 0xFF323232);
                }
            }
        }

        // 7. Floating Caption Buttons Capsule at top-right (x = rx + 453, y = ry + 1)
        let cap_x = rx + 453;
        let cap_y = ry + 1;
        surface.blit_raw_rgba(cap_x, cap_y, 104, 21, CAPSULE_104X21);

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
                        surface.draw_text(text_x + dx, text_y + dy, self.title, 0xFFFFFFFF, None);
                    }
                }
            }
            surface.draw_text(text_x, text_y, self.title, 0xFF202020, None);
        }
    }
}
