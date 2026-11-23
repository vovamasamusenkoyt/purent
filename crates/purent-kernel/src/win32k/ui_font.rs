//! Antialiased Noto Sans glyphs for GUI text. The console keeps its bitmap font.

use super::surface::Surface;
use purent_ntdef::composition::blend_over;

const SMALL_BYTES: usize = 95 * (1 + 16 * 19);
static ATLAS: &[u8; SMALL_BYTES + 95 * (1 + 36 * 42)] =
    include_bytes!("../../ui-font/dialog-ascii.bin");

pub struct Font {
    offset: usize,
    width: usize,
    height: usize,
}

pub const LABEL: Font = Font { offset: 0, width: 16, height: 19 };
pub const DISPLAY: Font = Font { offset: SMALL_BYTES, width: 36, height: 42 };

impl Font {
    fn glyph(&self, byte: u8) -> &[u8] {
        let byte = if (32..127).contains(&byte) { byte } else { b'?' };
        let size = 1 + self.width * self.height;
        let start = self.offset + (byte - 32) as usize * size;
        &ATLAS[start..start + size]
    }

    pub fn measure(&self, text: &str) -> i32 {
        text.bytes().map(|byte| i32::from(self.glyph(byte)[0])).sum()
    }

    pub fn draw(&self, surface: &mut Surface, mut x: i32, y: i32, text: &str, color: u32) {
        for byte in text.bytes() {
            let glyph = self.glyph(byte);
            for (index, &alpha) in glyph[1..].iter().enumerate() {
                if alpha == 0 {
                    continue;
                }
                let px = x + (index % self.width) as i32 - 1;
                let py = y + (index / self.width) as i32;
                let background = surface.get_pixel(px, py);
                let ink = (color & 0x00FF_FFFF) | (u32::from(alpha) << 24);
                let pixel = if background >> 24 == 255 {
                    blend_over(ink, background)
                } else {
                    let foreground_weight = u32::from(alpha);
                    let background_weight = ((background >> 24) * (255 - foreground_weight) + 127) / 255;
                    let opacity = foreground_weight + background_weight;
                    let channel = |shift: u32| {
                        let foreground = (ink >> shift) & 255;
                        let behind = (background >> shift) & 255;
                        ((foreground * foreground_weight + behind * background_weight + opacity / 2) / opacity) << shift
                    };
                    (opacity << 24) | channel(16) | channel(8) | channel(0)
                };
                surface.put_pixel(px, py, pixel);
            }
            x += i32::from(glyph[0]);
        }
    }
}
