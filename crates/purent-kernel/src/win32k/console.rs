//! PureNT Clean-Room Graphical Console Window
//! Streams live cmd.exe I/O directly into an interactive desktop window

use super::font::{FONT_HEIGHT, FONT_WIDTH};
use super::surface::{Rect, Surface};
use super::wnd::Window;

pub const CONSOLE_COLS: usize = 80;
pub const CONSOLE_ROWS: usize = 24;

pub struct ConsoleWindow {
    pub window: Window,
    pub buffer: [[u8; CONSOLE_COLS]; CONSOLE_ROWS],
    pub cursor_col: usize,
    pub cursor_row: usize,
}

impl ConsoleWindow {
    pub fn new(x: i32, y: i32) -> Self {
        let client_w = (CONSOLE_COLS * FONT_WIDTH) as u32; // 640
        let client_h = (CONSOLE_ROWS * FONT_HEIGHT) as u32; // 384
        let outer_w = client_w + 8; // 648
        let outer_h = client_h + 28 + 8; // 420

        Self {
            window: Window::new(
                0x1001,
                "C:\\Windows\\system32\\cmd.exe",
                Rect::new(x, y, outer_w, outer_h),
            ),
            buffer: [[b' '; CONSOLE_COLS]; CONSOLE_ROWS],
            cursor_col: 0,
            cursor_row: 0,
        }
    }

    pub fn clear(&mut self) {
        self.buffer = [[b' '; CONSOLE_COLS]; CONSOLE_ROWS];
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    pub fn write_char(&mut self, ch: u8) {
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
                // Backspace
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

    /// Renders the complete console window (frame + client text buffer + cursor)
    pub fn draw(&self, surface: &mut Surface) {
        // 1. Draw outer frame
        self.window.draw_frame(surface);

        // 2. Fill client background with console black
        let client = self.window.client_rect();
        surface.fill_rect(client, 0xFF0C0C0C);

        // 3. Render character matrix
        let start_x = client.x;
        let start_y = client.y;

        for r in 0..CONSOLE_ROWS {
            let row_y = start_y + (r * FONT_HEIGHT) as i32;
            for c in 0..CONSOLE_COLS {
                let col_x = start_x + (c * FONT_WIDTH) as i32;
                let ch = self.buffer[r][c] as char;
                if ch != ' ' {
                    surface.draw_char(col_x, row_y, ch, 0xFFCCCCCC, Some(0xFF0C0C0C));
                }
            }
        }

        // 4. Render blinking console underscore cursor
        if self.cursor_row < CONSOLE_ROWS && self.cursor_col < CONSOLE_COLS {
            let cur_x = start_x + (self.cursor_col * FONT_WIDTH) as i32;
            let cur_y = start_y + (self.cursor_row * FONT_HEIGHT) as i32 + (FONT_HEIGHT as i32 - 2);
            surface.fill_rect(Rect::new(cur_x, cur_y, FONT_WIDTH as u32, 2), 0xFFFFFFFF);
        }
    }
}
