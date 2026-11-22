//! Desktop backdrop sampling and glass filtering for DWM.

static WALLPAPER: &[u8] = include_bytes!("../../../../assets/wallpaper_640x400_rgb565.bin");

const WALL_WIDTH: usize = 640;
const WALL_HEIGHT: usize = 400;
const BLUR_WIDTH: usize = WALL_WIDTH / 4;
const BLUR_HEIGHT: usize = WALL_HEIGHT / 4;
const BLUR_WEIGHTS: [u32; 5] = [1, 4, 6, 4, 1];
static BLURRED_WALLPAPER: [u32; BLUR_WIDTH * BLUR_HEIGHT] = blur_wallpaper();

pub const fn wallpaper_pixel(x: usize, y: usize) -> u32 {
    let byte = (y * WALL_WIDTH + x) * 2;
    let rgb565 = u16::from_le_bytes([WALLPAPER[byte], WALLPAPER[byte + 1]]);
    let r = ((rgb565 >> 11) & 31) as u32 * 255 / 31;
    let g = ((rgb565 >> 5) & 63) as u32 * 255 / 63;
    let b = (rgb565 & 31) as u32 * 255 / 31;
    0xFF000000 | r << 16 | g << 8 | b
}

const fn blur_wallpaper() -> [u32; BLUR_WIDTH * BLUR_HEIGHT] {
    let mut horizontal = [0; BLUR_WIDTH * BLUR_HEIGHT];
    let mut blurred = [0; BLUR_WIDTH * BLUR_HEIGHT];
    let mut pass = 0;
    while pass < 2 {
        let mut y = 0;
        while y < BLUR_HEIGHT {
            let mut x = 0;
            while x < BLUR_WIDTH {
                let (mut r, mut g, mut b) = (0, 0, 0);
                let mut tap = 0;
                while tap < BLUR_WEIGHTS.len() {
                    let color = if pass == 0 {
                        let sx = (x + tap).saturating_sub(2);
                        let sx = if sx < BLUR_WIDTH { sx } else { BLUR_WIDTH - 1 };
                        wallpaper_pixel(sx * 4 + 2, y * 4 + 2)
                    } else {
                        let sy = (y + tap).saturating_sub(2);
                        let sy = if sy < BLUR_HEIGHT {
                            sy
                        } else {
                            BLUR_HEIGHT - 1
                        };
                        horizontal[sy * BLUR_WIDTH + x]
                    };
                    let weight = BLUR_WEIGHTS[tap];
                    r += ((color >> 16) & 255) * weight;
                    g += ((color >> 8) & 255) * weight;
                    b += (color & 255) * weight;
                    tap += 1;
                }
                let color = 0xFF000000 | (r / 16) << 16 | (g / 16) << 8 | (b / 16);
                if pass == 0 {
                    horizontal[y * BLUR_WIDTH + x] = color;
                } else {
                    blurred[y * BLUR_WIDTH + x] = color;
                }
                x += 1;
            }
            y += 1;
        }
        pass += 1;
    }
    blurred
}

pub fn glass_pixel(x: usize, y: usize, width: usize, height: usize) -> u32 {
    let row = y * BLUR_HEIGHT / height * BLUR_WIDTH;
    let col = x * BLUR_WIDTH / width;
    let background = BLURRED_WALLPAPER[row + col];
    0xFF000000 | (((background & 0x00FEFEFE) >> 1) + 0x00666A6E)
}
