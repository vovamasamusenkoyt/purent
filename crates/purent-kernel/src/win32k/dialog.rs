use purent_ntdef::dialog::DialogText;

use super::{surface::{Rect, Surface}, ui_font::{DISPLAY, LABEL}, wnd::{FrameControls, NonClient}};

pub const WIDTH: u32 = 430;
pub const HEIGHT: u32 = 236;
pub const CAPTION_HEIGHT: u32 = 35;
const BORDER: u32 = 7;

pub fn initial_bounds(width: u32, height: u32, slot: usize) -> Rect {
    let max_x = width.saturating_sub(WIDTH) as i32;
    let max_y = height.saturating_sub(HEIGHT) as i32;
    let offset = [0, 1, -1, 2][slot] * 36;
    Rect::new((max_x / 2 + offset).clamp(0, max_x), max_y / 2, WIDTH, HEIGHT)
}

pub fn caption(rect: Rect) -> Rect {
    non_client(rect).caption()
}

pub fn close_button(rect: Rect) -> Rect {
    non_client(rect).close_button()
}

pub fn ok_button(rect: Rect) -> Rect {
    Rect::new(rect.right() - 110, rect.bottom() - 48, 84, 27)
}

fn label(bytes: &[u8], limit: usize) -> &str {
    let len = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len.min(limit)]).unwrap_or("")
}

pub fn client(rect: Rect) -> Rect {
    Rect::new(
        rect.x + BORDER as i32,
        rect.y + CAPTION_HEIGHT as i32,
        rect.width - 2 * BORDER,
        rect.height - CAPTION_HEIGHT - BORDER,
    )
}

fn non_client(rect: Rect) -> NonClient {
    NonClient { frame: rect, client: client(rect), controls: FrameControls::Close }
}

pub fn draw(frame: &mut Surface, rect: Rect, text: &DialogText, redirected: bool, active: bool) {
    non_client(rect).draw(frame, label(&text.title, 40), 13, redirected, active);
    let panel = client(rect);
    frame.fill_rect(panel, 0xFFF5F8FC);
    frame.draw_rect(panel, 0xFF7890A5);
    let inset = panel.x + 21;
    let header = panel.y + 21;
    frame.fill_rect(Rect::new(inset, header + 5, 4, 50), 0xFF4383B3);
    DISPLAY.draw(frame, inset + 16, header - 4, label(&text.lines[0], 20), 0xFF192F46);
    LABEL.draw(frame, inset + 17, header + 36, label(&text.lines[1], 44), 0xFF4C6174);
    LABEL.draw(frame, inset, panel.y + 98, label(&text.lines[2], 44), 0xFF263C50);

    let footer_y = panel.bottom() - 60;
    frame.fill_rect(Rect::new(panel.x + 1, footer_y, panel.width - 2, 59), 0xFFEAF0F6);
    frame.fill_rect(Rect::new(panel.x + 1, footer_y, panel.width - 2, 1), 0xFFCDD9E4);
    let button = ok_button(rect);
    frame.draw_gradient_v(button, 0xFFFFFFFF, 0xFFD2E3F2);
    frame.draw_rect(button, 0xFF527FA8);
    frame.draw_rect(Rect::new(button.x + 1, button.y + 1, button.width - 2, button.height - 2), 0xFFF3F9FF);
    let title = label(&text.button, 8);
    let title_x = button.x + (button.width as i32 - LABEL.measure(title)) / 2;
    LABEL.draw(frame, title_x, button.y + 4, title, 0xFF1D3852);
}
