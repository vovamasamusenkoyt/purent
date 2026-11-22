//! PureNT Clean-Room Desktop
//! Renders the authentic Windows 7 Harmony desktop wallpaper across the entire screen

use super::surface::{Rect, Surface};

const CURSOR_WIDTH: usize = 11;
const CURSOR_HEIGHT: usize = 17;

static WALLPAPER_RGB565: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/wallpaper_640x400_rgb565.bin"));

const WALL_WIDTH: usize = 640;
const WALL_HEIGHT: usize = 400;
const fn wallpaper_pixel(x: usize, y: usize) -> u32 {
    let byte = (y * WALL_WIDTH + x) * 2;
    let rgb565 = u16::from_le_bytes([WALLPAPER_RGB565[byte], WALLPAPER_RGB565[byte + 1]]);
    let r = ((rgb565 >> 11) & 31) as u32 * 255 / 31;
    let g = ((rgb565 >> 5) & 63) as u32 * 255 / 63;
    let b = (rgb565 & 31) as u32 * 255 / 31;
    0xFF000000 | r << 16 | g << 8 | b
}

pub struct Desktop {
    pub width: u32,
    pub height: u32,
    pub mouse_x: i32,
    pub mouse_y: i32,
    cursor_underlay: [u32; CURSOR_WIDTH * CURSOR_HEIGHT],
}

impl Desktop {
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            mouse_x: (width / 2) as i32,
            mouse_y: (height / 2) as i32,
            cursor_underlay: [0; CURSOR_WIDTH * CURSOR_HEIGHT],
        }
    }

    /// Renders the official Windows 7 Harmony wallpaper covering the entire display
    pub fn draw_background(&self, surface: &mut Surface) {
        self.draw_background_region(surface, Rect::new(0, 0, self.width, self.height));
    }

    pub fn draw_background_region(&self, surface: &mut Surface, region: Rect) {
        let bounds = Rect::new(0, 0, self.width, self.height);
        let Some(region) = region.intersect(&bounds) else {
            return;
        };

        for y in region.y..region.bottom() {
            let src_y = y as usize * WALL_HEIGHT / self.height as usize;
            for x in region.x..region.right() {
                let src_x = x as usize * WALL_WIDTH / self.width as usize;
                surface.put_pixel(x, y, wallpaper_pixel(src_x, src_y));
            }
        }
    }

    pub fn restore_exposed_background(&self, surface: &mut Surface, old: Rect, new: Option<Rect>) {
        let Some(overlap) = new.and_then(|rect| old.intersect(&rect)) else {
            self.draw_background_region(surface, old);
            return;
        };
        for strip in [
            Rect::new(old.x, old.y, old.width, (overlap.y - old.y) as u32),
            Rect::new(old.x, overlap.bottom(), old.width, (old.bottom() - overlap.bottom()) as u32),
            Rect::new(old.x, overlap.y, (overlap.x - old.x) as u32, overlap.height),
            Rect::new(overlap.right(), overlap.y, (old.right() - overlap.right()) as u32, overlap.height),
        ] {
            self.draw_background_region(surface, strip);
        }
    }

    pub fn cursor_rect(&self) -> Rect {
        Rect::new(self.mouse_x, self.mouse_y, CURSOR_WIDTH as u32, CURSOR_HEIGHT as u32)
    }

    pub fn erase_cursor(&self, surface: &mut Surface) {
        for (index, &pixel) in self.cursor_underlay.iter().enumerate() {
            let x = self.mouse_x + (index % CURSOR_WIDTH) as i32;
            let y = self.mouse_y + (index / CURSOR_WIDTH) as i32;
            surface.put_pixel(x, y, pixel);
        }
    }

    pub fn draw_cursor(&mut self, surface: &mut Surface) {
        for (index, pixel) in self.cursor_underlay.iter_mut().enumerate() {
            let x = self.mouse_x + (index % CURSOR_WIDTH) as i32;
            let y = self.mouse_y + (index / CURSOR_WIDTH) as i32;
            *pixel = surface.get_pixel(x, y);
        }
        surface.draw_cursor(self.mouse_x, self.mouse_y);
    }
}
