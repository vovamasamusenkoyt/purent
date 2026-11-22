//! PureNT Clean-Room Desktop
//! Renders the authentic Windows 7 Harmony desktop wallpaper across the entire screen

use super::surface::Surface;

static WALLPAPER_RGB565: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/wallpaper_640x400_rgb565.bin"));

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
            mouse_y: 360,
        }
    }

    /// Renders the official Windows 7 Harmony wallpaper covering the entire display
    pub fn draw_background(&self, surface: &mut Surface) {
        let wall_u16 = unsafe {
            core::slice::from_raw_parts(
                WALLPAPER_RGB565.as_ptr() as *const u16,
                WALLPAPER_RGB565.len() / 2,
            )
        };

        for y in 0..self.height {
            let src_y = ((y as usize * 400) / self.height as usize).min(399);
            let row_offset = src_y * 640;
            for x in 0..self.width {
                let src_x = ((x as usize * 640) / self.width as usize).min(639);
                let pixel565 = wall_u16[row_offset + src_x];
                let r = (((pixel565 >> 11) & 0x1F) as u32 * 255) / 31;
                let g = (((pixel565 >> 5) & 0x3F) as u32 * 255) / 63;
                let b = ((pixel565 & 0x1F) as u32 * 255) / 31;
                let argb = 0xFF000000 | (r << 16) | (g << 8) | b;
                surface.put_pixel(x as i32, y as i32, argb);
            }
        }
    }

    /// Renders mouse cursor at current coordinates
    pub fn draw_cursor(&self, surface: &mut Surface) {
        surface.draw_cursor(self.mouse_x, self.mouse_y);
    }
}
