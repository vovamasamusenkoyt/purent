//! PureNT Clean-Room GDI Engine & TrueColor Surface
//! Implements hardware-independent 32-bpp ARGB blitting, clipping, gradients, and font rasterization

use super::font::{FONT_8X16, FONT_HEIGHT, FONT_WIDTH};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    pub fn right(&self) -> i32 {
        self.x + self.width as i32
    }

    pub fn bottom(&self) -> i32 {
        self.y + self.height as i32
    }

    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.right() && py >= self.y && py < self.bottom()
    }

    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let x1 = self.x.max(other.x);
        let y1 = self.y.max(other.y);
        let x2 = self.right().min(other.right());
        let y2 = self.bottom().min(other.bottom());
        if x2 > x1 && y2 > y1 {
            Some(Rect::new(x1, y1, (x2 - x1) as u32, (y2 - y1) as u32))
        } else {
            None
        }
    }
}

pub struct Surface {
    pub buffer: *mut u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

unsafe impl Send for Surface {}
unsafe impl Sync for Surface {}

impl Surface {
    pub const unsafe fn from_raw(buffer: *mut u32, width: u32, height: u32, stride: u32) -> Self {
        Self { buffer, width, height, stride }
    }

    #[inline(always)]
    pub fn put_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x >= 0 && (x as u32) < self.width && y >= 0 && (y as u32) < self.height {
            let offset = (y as u32 * self.stride + x as u32) as usize;
            unsafe {
                *self.buffer.add(offset) = color;
            }
        }
    }

    #[inline(always)]
    pub fn get_pixel(&self, x: i32, y: i32) -> u32 {
        if x >= 0 && (x as u32) < self.width && y >= 0 && (y as u32) < self.height {
            let offset = (y as u32 * self.stride + x as u32) as usize;
            unsafe { *self.buffer.add(offset) }
        } else {
            0
        }
    }

    pub fn fill_rect(&mut self, rect: Rect, color: u32) {
        let x1 = rect.x.max(0) as u32;
        let y1 = rect.y.max(0) as u32;
        let x2 = rect.right().clamp(0, self.width as i32) as u32;
        let y2 = rect.bottom().clamp(0, self.height as i32) as u32;

        if x1 >= x2 || y1 >= y2 {
            return;
        }

        for y in y1..y2 {
            let row_offset = (y * self.stride + x1) as usize;
            let len = (x2 - x1) as usize;
            unsafe {
                let ptr = self.buffer.add(row_offset);
                for i in 0..len {
                    *ptr.add(i) = color;
                }
            }
        }
    }

    /// Copies an opaque surface into this surface, clipping to the destination.
    ///
    /// The source and destination buffers must not overlap.
    pub unsafe fn blit_opaque(&mut self, source: &Surface, x: i32, y: i32) {
        let target = Rect::new(x, y, source.width, source.height);
        let bounds = Rect::new(0, 0, self.width, self.height);
        let Some(clipped) = target.intersect(&bounds) else {
            return;
        };
        let source_x = (clipped.x - x) as usize;
        let source_y = (clipped.y - y) as usize;
        for row in 0..clipped.height as usize {
            let src = (source_y + row) * source.stride as usize + source_x;
            let dst = (clipped.y as usize + row) * self.stride as usize + clipped.x as usize;
            core::ptr::copy_nonoverlapping(
                source.buffer.add(src),
                self.buffer.add(dst),
                clipped.width as usize,
            );
        }
    }

    pub fn draw_rect(&mut self, rect: Rect, color: u32) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        self.fill_rect(Rect::new(rect.x, rect.y, rect.width, 1), color);
        self.fill_rect(Rect::new(rect.x, rect.bottom() - 1, rect.width, 1), color);
        self.fill_rect(Rect::new(rect.x, rect.y, 1, rect.height), color);
        self.fill_rect(Rect::new(rect.right() - 1, rect.y, 1, rect.height), color);
    }

    /// Horizontal gradient fill (used for Windows 7 title bars and header strips)
    pub fn draw_gradient_h(&mut self, rect: Rect, start_color: u32, end_color: u32) {
        let x1 = rect.x.max(0) as u32;
        let y1 = rect.y.max(0) as u32;
        let x2 = rect.right().clamp(0, self.width as i32) as u32;
        let y2 = rect.bottom().clamp(0, self.height as i32) as u32;

        if x1 >= x2 || y1 >= y2 || rect.width == 0 {
            return;
        }

        let r1 = ((start_color >> 16) & 0xFF) as i32;
        let g1 = ((start_color >> 8) & 0xFF) as i32;
        let b1 = (start_color & 0xFF) as i32;

        let r2 = ((end_color >> 16) & 0xFF) as i32;
        let g2 = ((end_color >> 8) & 0xFF) as i32;
        let b2 = (end_color & 0xFF) as i32;

        let total_w = rect.width as i32;

        for x in x1..x2 {
            let t = (x as i32 - rect.x).min(total_w);
            let r = (r1 + ((r2 - r1) * t) / total_w) as u32;
            let g = (g1 + ((g2 - g1) * t) / total_w) as u32;
            let b = (b1 + ((b2 - b1) * t) / total_w) as u32;
            let color = 0xFF000000 | (r << 16) | (g << 8) | b;

            for y in y1..y2 {
                let offset = (y * self.stride + x) as usize;
                unsafe {
                    *self.buffer.add(offset) = color;
                }
            }
        }
    }

    /// Vertical gradient fill (used for taskbar and control backdrops)
    pub fn draw_gradient_v(&mut self, rect: Rect, start_color: u32, end_color: u32) {
        let x1 = rect.x.max(0) as u32;
        let y1 = rect.y.max(0) as u32;
        let x2 = rect.right().clamp(0, self.width as i32) as u32;
        let y2 = rect.bottom().clamp(0, self.height as i32) as u32;

        if x1 >= x2 || y1 >= y2 || rect.height == 0 {
            return;
        }

        let r1 = ((start_color >> 16) & 0xFF) as i32;
        let g1 = ((start_color >> 8) & 0xFF) as i32;
        let b1 = (start_color & 0xFF) as i32;

        let r2 = ((end_color >> 16) & 0xFF) as i32;
        let g2 = ((end_color >> 8) & 0xFF) as i32;
        let b2 = (end_color & 0xFF) as i32;

        let total_h = rect.height as i32;

        for y in y1..y2 {
            let t = (y as i32 - rect.y).min(total_h);
            let r = (r1 + ((r2 - r1) * t) / total_h) as u32;
            let g = (g1 + ((g2 - g1) * t) / total_h) as u32;
            let b = (b1 + ((b2 - b1) * t) / total_h) as u32;
            let color = 0xFF000000 | (r << 16) | (g << 8) | b;

            let row_offset = (y * self.stride + x1) as usize;
            let len = (x2 - x1) as usize;
            unsafe {
                let ptr = self.buffer.add(row_offset);
                for i in 0..len {
                    *ptr.add(i) = color;
                }
            }
        }
    }

    pub fn draw_char(&mut self, x: i32, y: i32, ch: char, fg: u32, bg: Option<u32>) {
        let ascii = ch as usize;
        let glyph = if ascii >= 32 && ascii < 128 {
            &FONT_8X16[ascii - 32]
        } else {
            &FONT_8X16[63 - 32] // '?'
        };

        for row in 0..FONT_HEIGHT {
            let py = y + row as i32;
            if py < 0 || (py as u32) >= self.height {
                continue;
            }
            let byte = glyph[row];
            for col in 0..FONT_WIDTH {
                let px = x + col as i32;
                if px < 0 || (px as u32) >= self.width {
                    continue;
                }
                if (byte & (0x80 >> col)) != 0 {
                    self.put_pixel(px, py, fg);
                } else if let Some(bg_color) = bg {
                    self.put_pixel(px, py, bg_color);
                }
            }
        }
    }

    pub fn draw_text(&mut self, mut x: i32, y: i32, text: &str, fg: u32, bg: Option<u32>) {
        for ch in text.chars() {
            if ch == '\n' {
                break;
            }
            self.draw_char(x, y, ch, fg, bg);
            x += FONT_WIDTH as i32;
        }
    }

    /// Blit raw 32-bpp RGBA bitmap with per-pixel alpha blending
    pub fn blit_raw_rgba(&mut self, x: i32, y: i32, w: u32, h: u32, data: &[u8]) {
        for row in 0..h {
            let py = y + row as i32;
            if py < 0 || (py as u32) >= self.height {
                continue;
            }
            for col in 0..w {
                let px = x + col as i32;
                if px < 0 || (px as u32) >= self.width {
                    continue;
                }
                let idx = ((row * w + col) * 4) as usize;
                if idx + 3 < data.len() {
                    let r = data[idx] as u32;
                    let g = data[idx + 1] as u32;
                    let b = data[idx + 2] as u32;
                    let a = data[idx + 3] as u32;
                    if a == 255 {
                        self.put_pixel(px, py, 0xFF000000 | (r << 16) | (g << 8) | b);
                    } else if a > 0 {
                        let dst = self.get_pixel(px, py);
                        let dr = (dst >> 16) & 0xFF;
                        let dg = (dst >> 8) & 0xFF;
                        let db = dst & 0xFF;
                        let out_r = (r * a + dr * (255 - a)) / 255;
                        let out_g = (g * a + dg * (255 - a)) / 255;
                        let out_b = (b * a + db * (255 - a)) / 255;
                        self.put_pixel(px, py, 0xFF000000 | (out_r << 16) | (out_g << 8) | out_b);
                    }
                }
            }
        }
    }

    /// Windows 7 caption button (Close [X], Maximize [□], Minimize [_])
    pub fn draw_caption_button(&mut self, rect: Rect, btn_type: CaptionButtonType, is_close: bool) {
        // Base button background
        let bg_color = if is_close {
            0xFFC75050 // Windows 7 Close red-glass tone
        } else {
            0xFF3B597B // Slate-blue glass tone
        };
        self.fill_rect(rect, bg_color);
        self.draw_rect(rect, 0xFF2A3E54); // subtle border

        let cx = rect.x + (rect.width as i32) / 2;
        let cy = rect.y + (rect.height as i32) / 2;
        let glyph_color = 0xFFFFFFFF; // Crisp white symbol

        match btn_type {
            CaptionButtonType::Close => {
                // Diagonal cross
                for d in -4..=4 {
                    self.put_pixel(cx + d, cy + d, glyph_color);
                    self.put_pixel(cx + d + 1, cy + d, glyph_color);
                    self.put_pixel(cx + d, cy - d, glyph_color);
                    self.put_pixel(cx + d + 1, cy - d, glyph_color);
                }
            }
            CaptionButtonType::Maximize => {
                // Square box
                self.draw_rect(Rect::new(cx - 5, cy - 5, 10, 10), glyph_color);
                self.draw_rect(Rect::new(cx - 5, cy - 4, 10, 2), glyph_color); // thicker top
            }
            CaptionButtonType::Minimize => {
                // Underscore line
                self.fill_rect(Rect::new(cx - 5, cy + 3, 10, 2), glyph_color);
            }
        }
    }

    /// Windows 7 standard Aero Arrow cursor (12x19 pixels)
    pub fn draw_cursor(&mut self, x: i32, y: i32) {
        #[rustfmt::skip]
        static CURSOR_BITMAP: [&str; 19] = [
            "X               ",
            "XX              ",
            "X.X             ",
            "X..X            ",
            "X...X           ",
            "X....X          ",
            "X.....X         ",
            "X......X        ",
            "X.......X       ",
            "X........X      ",
            "X.....XXXXX     ",
            "X..X..X         ",
            "X.X X..X        ",
            "XX   X..X       ",
            "X     X..X      ",
            "      X..X      ",
            "       XX       ",
            "                ",
            "                ",
        ];

        for (row, line) in CURSOR_BITMAP.iter().enumerate() {
            let py = y + row as i32;
            for (col, ch) in line.chars().enumerate() {
                let px = x + col as i32;
                match ch {
                    'X' => self.put_pixel(px, py, 0xFF000000), // Black outline
                    '.' => self.put_pixel(px, py, 0xFFFFFFFF), // White interior
                    _ => {}
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CaptionButtonType {
    Close,
    Maximize,
    Minimize,
}
