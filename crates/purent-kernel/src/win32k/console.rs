//! PureNT Clean-Room Graphical Console Window
//! Streams live cmd.exe I/O directly into an interactive desktop window matching Windows 7 SP1

use super::font::FONT_WIDTH;
use super::surface::{Rect, Surface};
use super::wnd::Window;
use crate::mm::pool::{ExAllocatePoolWithTag, NonPagedPool};

pub const CONSOLE_COLS: usize = 65;
pub const CONSOLE_ROWS: usize = 18;

const TEXT_X: i32 = 10;
const TEXT_Y: i32 = 32;
const TEXT_WIDTH: u32 = 528;
const TEXT_HEIGHT: u32 = 288;

static SCROLL_UP: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_up.raw"));
static SCROLL_DOWN: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_down.raw"));
static SCROLL_LEFT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_left.raw"));
static SCROLL_RIGHT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_right.raw"));
static SCROLL_VTHUMB_26: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_vthumb_26.raw"));
static SCROLL_HTHUMB_406: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_hthumb_406.raw"));
static SCROLL_GRIP: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/scroll_grip.raw"));

pub struct ConsoleWindow {
    pub window: Window,
    pub buffer: [[u8; CONSOLE_COLS]; CONSOLE_ROWS],
    pub cursor_col: usize,
    pub cursor_row: usize,
    text_surface: Surface,
    text_dirty: bool,
}

impl ConsoleWindow {
    pub fn new(x: i32, y: i32) -> Option<Self> {
        // The console and its surface live for the lifetime of Win32k.
        let text_surface = unsafe {
            let bytes = (TEXT_WIDTH * TEXT_HEIGHT) as usize * core::mem::size_of::<u32>();
            let pixels = ExAllocatePoolWithTag(NonPagedPool, bytes, u32::from_le_bytes(*b"ConS"));
            if pixels.is_null() {
                return None;
            }
            Surface::from_raw(pixels.cast(), TEXT_WIDTH, TEXT_HEIGHT, TEXT_WIDTH)
        };
        // Authentic Windows 7 565x347 window geometry
        let outer_w = 565;
        let outer_h = 347;

        Some(Self {
            window: Window::new(
                0x1001,
                "PureNT Console",
                Rect::new(x, y, outer_w, outer_h),
            ),
            buffer: [[b' '; CONSOLE_COLS]; CONSOLE_ROWS],
            cursor_col: 0,
            cursor_row: 0,
            text_surface,
            text_dirty: true,
        })
    }

    pub fn clear(&mut self) {
        self.buffer = [[b' '; CONSOLE_COLS]; CONSOLE_ROWS];
        self.cursor_col = 0;
        self.cursor_row = 0;
        self.text_dirty = true;
    }

    pub fn write_char(&mut self, ch: u8) {
        self.text_dirty = true;
        match ch {
            b'\r' => {
                self.cursor_col = 0;
            }
            b'\n' => {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= CONSOLE_ROWS {
                    self.scroll();
                }
            }
            b'\x08' => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.buffer[self.cursor_row][self.cursor_col] = b' ';
                }
            }
            b'\t' => {
                let next_tab = (self.cursor_col + 8) & !7;
                while self.cursor_col < next_tab && self.cursor_col < CONSOLE_COLS {
                    self.buffer[self.cursor_row][self.cursor_col] = b' ';
                    self.cursor_col += 1;
                }
            }
            byte if byte >= 32 && byte <= 126 => {
                if self.cursor_col >= CONSOLE_COLS {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= CONSOLE_ROWS {
                        self.scroll();
                    }
                }
                self.buffer[self.cursor_row][self.cursor_col] = byte;
                self.cursor_col += 1;
            }
            _ => {}
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.write_char(b);
        }
    }

    fn scroll(&mut self) {
        for r in 1..CONSOLE_ROWS {
            self.buffer[r - 1] = self.buffer[r];
        }
        self.buffer[CONSOLE_ROWS - 1] = [b' '; CONSOLE_COLS];
        self.cursor_row = CONSOLE_ROWS - 1;
    }

    fn rasterize_text(&mut self) {
        let surface = &mut self.text_surface;
        surface.fill_rect(Rect::new(0, 0, TEXT_WIDTH, TEXT_HEIGHT), 0xFF000000);

        let line_height = 13;
        for (row, line) in self.buffer.iter().enumerate() {
            let y = 1 + row as i32 * line_height;
            for (col, &byte) in line.iter().enumerate() {
                if byte != b' ' {
                    let x = (col * FONT_WIDTH) as i32;
                    surface.draw_char(x, y, byte as char, 0xFFC0C0C0, Some(0xFF000000));
                }
            }
        }

        if self.cursor_row < CONSOLE_ROWS && self.cursor_col < CONSOLE_COLS {
            let x = (self.cursor_col * FONT_WIDTH) as i32;
            let y = 11 + self.cursor_row as i32 * line_height;
            surface.fill_rect(Rect::new(x, y, FONT_WIDTH as u32, 2), 0xFFC0C0C0);
        }
        self.text_dirty = false;
    }

    pub fn text_rect(&self) -> Rect {
        Rect::new(
            self.window.rect.x + TEXT_X,
            self.window.rect.y + TEXT_Y,
            TEXT_WIDTH,
            TEXT_HEIGHT,
        )
    }

    pub fn draw_text_surface(&mut self, surface: &mut Surface) {
        self.draw_text_at(surface, self.text_rect());
    }

    pub fn draw_redirected_text(&mut self, surface: &mut Surface) {
        self.draw_text_at(surface, Rect::new(TEXT_X, TEXT_Y, TEXT_WIDTH, TEXT_HEIGHT));
    }

    fn draw_text_at(&mut self, surface: &mut Surface, rect: Rect) {
        if self.text_dirty {
            self.rasterize_text();
        }
        // The console's pixel buffer is separate from the composition target.
        unsafe { surface.blit_opaque(&self.text_surface, rect.x, rect.y) };
    }

    pub fn draw(&mut self, surface: &mut Surface, redirected: bool) {
        if self.window.is_minimized {
            return;
        }

        let mut window = self.window;
        if redirected {
            window.rect.x = 0;
            window.rect.y = 0;
        }
        let rx = window.rect.x;
        let ry = window.rect.y;
        window.draw_chrome(surface, redirected);
        if redirected {
            self.draw_redirected_text(surface);
        } else {
            self.draw_text_surface(surface);
        }

        // 5. Vertical Scrollbar (x = rx + 538..rx + 555, y = ry + 32..ry + 320)
        let vx = rx + 538;
        let vy = ry + 32;

        // Up arrow button (17x16)
        surface.blit_raw_rgba(vx, vy, 17, 16, SCROLL_UP);

        // Vertical thumb pill (17x26 at y = vy + 16)
        surface.blit_raw_rgba(vx, vy + 16, 17, 26, SCROLL_VTHUMB_26);

        // Scrollbar vertical track (y = vy + 42..ry + 303)
        let vtrack_top = vy + 42;
        let vtrack_bot = ry + 303;
        surface.draw_gradient_h(
            Rect::new(vx, vtrack_top, 17, (vtrack_bot - vtrack_top) as u32),
            0xFFF0F0F0,
            0xFFE6E6E6,
        );

        // Down arrow button (17x17 at ry + 303)
        surface.blit_raw_rgba(vx, ry + 303, 17, 17, SCROLL_DOWN);

        // 6. Horizontal Scrollbar (x = rx + 10..rx + 538, y = ry + 320..ry + 337)
        let hx = rx + 10;
        let hy = ry + 320;

        // Left arrow button (17x17)
        surface.blit_raw_rgba(hx, hy, 17, 17, SCROLL_LEFT);

        // Horizontal thumb pill (406x17 at x = hx + 17)
        surface.blit_raw_rgba(hx + 17, hy, 406, 17, SCROLL_HTHUMB_406);

        // Horizontal track (x = hx + 423..rx + 521)
        surface.draw_gradient_v(
            Rect::new(hx + 423, hy, (rx + 521 - (hx + 423)) as u32, 17),
            0xFFF0F0F0,
            0xFFE6E6E6,
        );

        // Right arrow button (17x17 at rx + 521)
        surface.blit_raw_rgba(rx + 521, hy, 17, 17, SCROLL_RIGHT);

        // 7. Diagonal Size Grip (17x17 at rx + 538, ry + 320)
        surface.blit_raw_rgba(vx, hy, 17, 17, SCROLL_GRIP);
    }
}
