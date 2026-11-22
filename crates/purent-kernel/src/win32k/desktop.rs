//! PureNT Clean-Room Desktop & Taskbar (Shell_TrayWnd)
//! Renders the authentic Windows 7 Harmony desktop wallpaper and Superbar

use super::surface::{Rect, Surface};

pub const TASKBAR_HEIGHT: u32 = 40;

static WALLPAPER_RGB565: &[u8] = include_bytes!("wallpaper_640x400_rgb565.bin");

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

    /// Renders the official Windows 7 Harmony wallpaper and bottom Superbar
    pub fn draw_background(&self, surface: &mut Surface) {
        let desk_h = self.height.saturating_sub(TASKBAR_HEIGHT);

        // 1. Official Windows 7 Harmony Wallpaper (sampled 2x2 from 640x400 RGB565)
        let wall_u16 = unsafe {
            core::slice::from_raw_parts(
                WALLPAPER_RGB565.as_ptr() as *const u16,
                WALLPAPER_RGB565.len() / 2,
            )
        };

        for y in 0..desk_h {
            let src_y = (y as usize / 2).min(399);
            let row_offset = src_y * 640;
            for x in 0..self.width {
                let src_x = (x as usize / 2).min(639);
                let pixel565 = wall_u16[row_offset + src_x];
                let r = (((pixel565 >> 11) & 0x1F) as u32 * 255) / 31;
                let g = (((pixel565 >> 5) & 0x3F) as u32 * 255) / 63;
                let b = ((pixel565 & 0x1F) as u32 * 255) / 31;
                let argb = 0xFF000000 | (r << 16) | (g << 8) | b;
                surface.put_pixel(x as i32, y as i32, argb);
            }
        }

        // 2. Windows 7 Superbar (Bottom 40px)
        let taskbar_y = self.height as i32 - TASKBAR_HEIGHT as i32;
        let taskbar_w = self.width as i32;

        // Dark Slate Glass Vertical Gradient
        for y_rel in 0..TASKBAR_HEIGHT as i32 {
            let py = taskbar_y + y_rel;
            let color = if y_rel == 0 {
                0xFF557391 // Top specular highlight
            } else if y_rel < 16 {
                // Upper glass reflection
                let t = y_rel as u32;
                let r = 36 - ((36 - 24) * t) / 16;
                let g = 52 - ((52 - 36) * t) / 16;
                let b = 72 - ((72 - 50) * t) / 16;
                0xFF000000 | (r << 16) | (g << 8) | b
            } else {
                // Deep dark slate glass
                let t = (y_rel - 16) as u32;
                let r = 20 - ((20 - 10) * t) / 24;
                let g = 30 - ((30 - 16) * t) / 24;
                let b = 44 - ((44 - 24) * t) / 24;
                0xFF000000 | (r << 16) | (g << 8) | b
            };

            for px in 0..taskbar_w {
                surface.put_pixel(px, py, color);
            }
        }

        // 3. Windows 7 Circular Start Orb (Radius 17px, centered at x = 24, y = taskbar_y + 18)
        let orb_cx = 24;
        let orb_cy = taskbar_y + 18;
        let orb_r = 17;

        for dy in -orb_r..=orb_r {
            for dx in -orb_r..=orb_r {
                let dist_sq = dx * dx + dy * dy;
                if dist_sq <= orb_r * orb_r {
                    let px = orb_cx + dx;
                    let py = orb_cy + dy;

                    let color = if dist_sq >= (orb_r - 1) * (orb_r - 1) {
                        0xFFA0BEDC // Metallic silver outer rim
                    } else {
                        // Spherical radial glass gradient (light from top-left)
                        let d = (dx + 5) * (dx + 5) + (dy + 5) * (dy + 5);
                        let t = (d as u32).min(orb_r as u32 * orb_r as u32 * 2);
                        let max_d = orb_r as u32 * orb_r as u32 * 2;
                        let r = 50 - ((50 - 12) * t) / max_d;
                        let g = 120 - ((120 - 38) * t) / max_d;
                        let b = 210 - ((210 - 80) * t) / max_d;
                        0xFF000000 | (r << 16) | (g << 8) | b
                    };

                    surface.put_pixel(px, py, color);
                }
            }
        }

        // 4-Color Windows Flag inside Start Orb
        // Red (top-left)
        for dy in -6..-1 {
            for dx in -7..-1 {
                surface.put_pixel(orb_cx + dx, orb_cy + dy, 0xFFF03C28);
            }
        }
        // Green (top-right)
        for dy in -6..-1 {
            for dx in 1..7 {
                surface.put_pixel(orb_cx + dx, orb_cy + dy, 0xFF78C828);
            }
        }
        // Blue (bottom-left)
        for dy in 1..6 {
            for dx in -7..-1 {
                surface.put_pixel(orb_cx + dx, orb_cy + dy, 0xFF1E8CF0);
            }
        }
        // Yellow (bottom-right)
        for dy in 1..6 {
            for dx in 1..7 {
                surface.put_pixel(orb_cx + dx, orb_cy + dy, 0xFFFFC81E);
            }
        }

        // 4. Active Superbar Task Pill for cmd.exe at x = 54, width = 54
        let pill_x = 54;
        let pill_w = 54;
        for y_rel in 2..(TASKBAR_HEIGHT as i32 - 2) {
            let py = taskbar_y + y_rel;
            let t = y_rel as u32;
            let r = 30 + (10 * t) / 36;
            let g = 60 + (20 * t) / 36;
            let b = 100 + (30 * t) / 36;
            let color = 0xFF000000 | (r << 16) | (g << 8) | b;
            for px in pill_x..(pill_x + pill_w) {
                surface.put_pixel(px, py, color);
            }
        }
        // Cyan bottom active indicator line (2px tall)
        for px in (pill_x + 4)..(pill_x + pill_w - 4) {
            surface.put_pixel(px, taskbar_y + TASKBAR_HEIGHT as i32 - 2, 0xFF00B4FF);
            surface.put_pixel(px, taskbar_y + TASKBAR_HEIGHT as i32 - 3, 0xFF00B4FF);
        }
        // 16x16 Command Prompt icon inside taskbar pill
        let p_icon_x = pill_x + 19;
        let p_icon_y = taskbar_y + 11;
        surface.draw_rect(Rect::new(p_icon_x, p_icon_y, 16, 14), 0xFFB4C0CC);
        surface.fill_rect(Rect::new(p_icon_x + 1, p_icon_y + 1, 14, 12), 0xFF0C0C0C);
        for px in (p_icon_x + 1)..(p_icon_x + 15) {
            surface.put_pixel(px, p_icon_y + 1, 0xFF3C6EA5);
            surface.put_pixel(px, p_icon_y + 2, 0xFF3C6EA5);
        }
        surface.put_pixel(p_icon_x + 3, p_icon_y + 5, 0xFFFFFFFF);
        surface.put_pixel(p_icon_x + 3, p_icon_y + 6, 0xFFFFFFFF);
        surface.put_pixel(p_icon_x + 4, p_icon_y + 5, 0xFFFFFFFF);
        surface.put_pixel(p_icon_x + 6, p_icon_y + 6, 0xFFFFFFFF);
        surface.put_pixel(p_icon_x + 8, p_icon_y + 8, 0xFFFFFFFF);
        surface.put_pixel(p_icon_x + 9, p_icon_y + 8, 0xFFFFFFFF);

        // 5. System Tray: Stacked Clock and Date on the right
        let clock_x = taskbar_w - 80;
        surface.draw_text(clock_x, taskbar_y + 5, "22:25", 0xFFE6F0FA, None);
        surface.draw_text(clock_x - 10, taskbar_y + 21, "22.11.2026", 0xFFC8D7E6, None);

        // Aero Peek strip on the far right (12px wide)
        let peek_x = taskbar_w - 12;
        surface.fill_rect(
            Rect::new(peek_x, taskbar_y + 1, 12, TASKBAR_HEIGHT - 2),
            0xFF283C50,
        );
        surface.draw_rect(
            Rect::new(peek_x, taskbar_y + 1, 12, TASKBAR_HEIGHT - 2),
            0xFF5A7896,
        );
    }

    /// Renders mouse cursor at current coordinates
    pub fn draw_cursor(&self, surface: &mut Surface) {
        surface.draw_cursor(self.mouse_x, self.mouse_y);
    }
}
