//! PureNT Clean-Room Window Management Subsystem
//! Window frame rendering, non-client area calculation, and Z-order dispatch matching Windows 7 SP1

use super::surface::{Rect, Surface};

pub const BORDER_WIDTH: u32 = 6;
pub const CAPTION_HEIGHT: u32 = 30;

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
            self.rect.y + CAPTION_HEIGHT as i32,
            self.rect.width.saturating_sub(BORDER_WIDTH * 2),
            self.rect.height.saturating_sub(CAPTION_HEIGHT + BORDER_WIDTH),
        )
    }

    /// Renders the authentic Windows 7 Aero Glass / Basic Window Frame
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

        // 1. Titlebar: Authentic Dual-Zone Windows 7 Aero Glass Gradient (0..30px)
        for y_rel in 0..CAPTION_HEIGHT as i32 {
            let py = ry + y_rel;
            let color = if y_rel == 0 {
                0xFFDCEBFA // Top specular highlight
            } else if y_rel < 14 {
                // Upper zone: soft sky-glass sheen (0xFFB8D4EF -> 0xFF86B4DF)
                let t = y_rel as u32;
                let r = 184 - ((184 - 134) * t) / 14;
                let g = 212 - ((212 - 180) * t) / 14;
                let b = 239 - ((239 - 223) * t) / 14;
                0xFF000000 | (r << 16) | (g << 8) | b
            } else if y_rel == 14 {
                0xFFC3DEF8 // Mid-horizon specular ridge line
            } else {
                // Lower zone: deep Aero blue gradient (0xFF5A94CB -> 0xFF3C72A8)
                let t = (y_rel - 15) as u32;
                let r = 90 - ((90 - 60) * t) / 15;
                let g = 148 - ((148 - 114) * t) / 15;
                let b = 203 - ((203 - 168) * t) / 15;
                0xFF000000 | (r << 16) | (g << 8) | b
            };

            for px in rx..right {
                surface.put_pixel(px, py, color);
            }
        }

        // 2. Left and Right Glass Borders (6px wide)
        for x_rel in 0..BORDER_WIDTH as i32 {
            let lx = rx + x_rel;
            let rrx = right - 1 - x_rel;
            let color = if x_rel == 0 {
                0xFF274868 // Outer 1px frame line
            } else if x_rel == (BORDER_WIDTH as i32 - 1) {
                0xFF18324C // Inner client separator line
            } else {
                let t = x_rel as u32;
                let r = 122 - ((122 - 77) * t) / 6;
                let g = 170 - ((170 - 128) * t) / 6;
                let b = 212 - ((212 - 174) * t) / 6;
                0xFF000000 | (r << 16) | (g << 8) | b
            };

            for py in (ry + CAPTION_HEIGHT as i32)..bottom {
                surface.put_pixel(lx, py, color);
                surface.put_pixel(rrx, py, color);
            }
        }

        // 3. Bottom Glass Border (6px tall)
        for y_rel in 0..BORDER_WIDTH as i32 {
            let py = bottom - BORDER_WIDTH as i32 + y_rel;
            let color = if y_rel == (BORDER_WIDTH as i32 - 1) {
                0xFF274868 // Bottom-most 1px edge
            } else {
                let t = y_rel as u32;
                let r = 100 - ((100 - 60) * t) / 6;
                let g = 150 - ((150 - 110) * t) / 6;
                let b = 190 - ((190 - 160) * t) / 6;
                0xFF000000 | (r << 16) | (g << 8) | b
            };

            for px in rx..right {
                surface.put_pixel(px, py, color);
            }
        }

        // 4. Client Area Boundary Box
        let client = self.client_rect();
        surface.draw_rect(
            Rect::new(client.x - 1, client.y - 1, client.width + 2, client.height + 2),
            0xFF18324C,
        );

        // 5. Rounded Top Corners (Radius 6px) - smooth anti-aliased corner curves
        let radius = 6;
        for j in 0..radius {
            for i in 0..radius {
                let dist_sq = (radius - 1 - i) * (radius - 1 - i) + (radius - 1 - j) * (radius - 1 - j);
                if dist_sq > (radius * radius - 2) {
                    // Soften or transparent edge for rounded window appearance
                    let edge_color = 0xFF1B3A5A;
                    surface.put_pixel(rx + i, ry + j, edge_color);
                    surface.put_pixel(right - 1 - i, ry + j, edge_color);
                }
            }
        }

        // 6. Docked Caption Buttons Cluster at top-right
        let btn_h = 20;
        let btn_y = ry + 1;

        // Close button: 48px wide, docked against right border
        let close_w = 48;
        let close_x = right - close_w - 1;
        for y_rel in 0..btn_h {
            let py = btn_y + y_rel;
            let color = if y_rel == 0 {
                0xFFF28D8D // Top specular highlight line
            } else if y_rel < 10 {
                // Upper crimson red gradient (0xFFE04343 -> 0xFFC92828)
                let t = y_rel as u32;
                let r = 224 - ((224 - 201) * t) / 10;
                let g = 67 - ((67 - 40) * t) / 10;
                let b = 67 - ((67 - 40) * t) / 10;
                0xFF000000 | (r << 16) | (g << 8) | b
            } else {
                // Lower dark crimson gradient (0xFFAE1B1B -> 0xFF8F1212)
                let t = (y_rel - 10) as u32;
                let r = 174 - ((174 - 143) * t) / 10;
                let g = 27 - ((27 - 18) * t) / 10;
                let b = 27 - ((27 - 18) * t) / 10;
                0xFF000000 | (r << 16) | (g << 8) | b
            };

            for px in close_x..(right - 1) {
                surface.put_pixel(px, py, color);
            }
        }
        // Close button borders
        for py in btn_y..(btn_y + btn_h) {
            surface.put_pixel(close_x, py, 0xFF680D0D);
        }
        for px in close_x..(right - 1) {
            surface.put_pixel(px, btn_y + btn_h - 1, 0xFF680D0D);
        }

        // Close button 'X' glyph: Bold white cross centered in button
        let cx = close_x + close_w / 2;
        let cy = btn_y + btn_h / 2;
        for d in -4..=4 {
            surface.put_pixel(cx + d, cy + d, 0xFFFFFFFF);
            surface.put_pixel(cx + d + 1, cy + d, 0xFFFFFFFF);
            surface.put_pixel(cx + d, cy - d, 0xFFFFFFFF);
            surface.put_pixel(cx + d + 1, cy - d, 0xFFFFFFFF);
        }

        // Maximize and Minimize buttons: 30px wide each
        let btn_w = 30;
        let max_x = close_x - btn_w;
        let min_x = max_x - btn_w;

        for &bx in &[min_x, max_x] {
            for y_rel in 0..btn_h {
                let py = btn_y + y_rel;
                let color = if y_rel == 0 {
                    0xFFEBF4FD
                } else if y_rel < 10 {
                    let t = y_rel as u32;
                    let r = 200 - ((200 - 164) * t) / 10;
                    let g = 224 - ((224 - 200) * t) / 10;
                    let b = 244 - ((244 - 232) * t) / 10;
                    0xFF000000 | (r << 16) | (g << 8) | b
                } else {
                    let t = (y_rel - 10) as u32;
                    let r = 130 - ((130 - 102) * t) / 10;
                    let g = 173 - ((173 - 150) * t) / 10;
                    let b = 214 - ((214 - 194) * t) / 10;
                    0xFF000000 | (r << 16) | (g << 8) | b
                };

                for px in bx..(bx + btn_w) {
                    surface.put_pixel(px, py, color);
                }
            }
            // Vertical and bottom divider lines
            for py in btn_y..(btn_y + btn_h) {
                surface.put_pixel(bx, py, 0xFF386084);
            }
            for px in bx..(bx + btn_w) {
                surface.put_pixel(px, btn_y + btn_h - 1, 0xFF386084);
            }
        }

        // Maximize Glyph: 10x9 box with 2px thick top bar
        let mcx = max_x + btn_w / 2;
        let mcy = btn_y + btn_h / 2;
        surface.draw_rect(Rect::new(mcx - 5, mcy - 4, 10, 9), 0xFF1E1E1E);
        for px in (mcx - 5)..=(mcx + 4) {
            surface.put_pixel(px, mcy - 3, 0xFF1E1E1E);
        }

        // Minimize Glyph: 11px wide, 2px tall bar
        let micx = min_x + btn_w / 2;
        let micy = btn_y + btn_h / 2;
        for px in (micx - 5)..=(micx + 5) {
            surface.put_pixel(px, micy + 3, 0xFF1E1E1E);
            surface.put_pixel(px, micy + 4, 0xFF1E1E1E);
        }

        // 7. 16x16 Application Icon (Windows 7 cmd.exe icon)
        let icon_x = rx + 9;
        let icon_y = ry + 7;
        // Outer console bezel
        surface.draw_rect(Rect::new(icon_x, icon_y, 16, 15), 0xFFBEC8D2);
        // Console client black
        surface.fill_rect(Rect::new(icon_x + 1, icon_y + 1, 14, 13), 0xFF0C0C0C);
        // Top miniature titlebar
        for px in (icon_x + 1)..(icon_x + 15) {
            surface.put_pixel(px, icon_y + 1, 0xFF3C6EA5);
            surface.put_pixel(px, icon_y + 2, 0xFF3C6EA5);
        }
        // "C:\_" prompt glyph inside icon
        surface.put_pixel(icon_x + 3, icon_y + 5, 0xFFFFFFFF);
        surface.put_pixel(icon_x + 3, icon_y + 6, 0xFFFFFFFF);
        surface.put_pixel(icon_x + 4, icon_y + 5, 0xFFFFFFFF);
        surface.put_pixel(icon_x + 6, icon_y + 6, 0xFFFFFFFF);
        surface.put_pixel(icon_x + 8, icon_y + 8, 0xFFFFFFFF);
        surface.put_pixel(icon_x + 9, icon_y + 8, 0xFFFFFFFF);

        // 8. Title Text with Aero Glow / Halo
        let text_x = rx + 32;
        let text_y = ry + 7;
        // White diffuse halo in 8 directions for Aero glass readability
        for &dx in &[-1, 1, 0] {
            for &dy in &[-1, 1, 0] {
                if dx != 0 || dy != 0 {
                    surface.draw_text(text_x + dx, text_y + dy, self.title, 0xFFE0EEFA, None);
                }
            }
        }
        // Crisp dark foreground title text
        surface.draw_text(text_x, text_y, self.title, 0xFF141414, None);
    }
}
