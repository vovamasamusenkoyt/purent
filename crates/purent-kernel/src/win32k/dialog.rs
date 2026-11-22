use core::sync::atomic::{AtomicU8, Ordering};

use purent_ntdef::dialog::DialogText;

use super::surface::{Rect, Surface};

const CLOSED: u8 = 0;
const REQUESTED: u8 = 1;
const VISIBLE: u8 = 2;
const DISMISSED: u8 = 3;
static STATE: AtomicU8 = AtomicU8::new(CLOSED);

pub fn request() -> bool {
    STATE
        .compare_exchange(CLOSED, REQUESTED, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub fn open_requested() -> bool {
    STATE
        .compare_exchange(REQUESTED, VISIBLE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub fn pending() -> bool {
    STATE.load(Ordering::Acquire) != DISMISSED
}

pub fn visible() -> bool {
    STATE.load(Ordering::Acquire) == VISIBLE
}

pub fn dismiss() {
    STATE.store(DISMISSED, Ordering::Release);
}

pub fn finish() {
    STATE.store(CLOSED, Ordering::Release);
}

pub fn bounds(width: u32, height: u32) -> Rect {
    Rect::new(
        (width as i32 - 370) / 2,
        (height as i32 - 174) / 2,
        370,
        174,
    )
}

pub fn ok_button(rect: Rect) -> Rect {
    Rect::new(rect.right() - 95, rect.bottom() - 37, 75, 24)
}

fn label(bytes: &[u8], limit: usize) -> &str {
    let len = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len.min(limit)]).unwrap_or("")
}

pub fn draw(frame: &mut Surface, text: &DialogText) {
    let rect = bounds(frame.width, frame.height);
    frame.fill_rect(rect, 0xFFF2F5F7);
    frame.fill_rect(Rect::new(rect.x, rect.y, rect.width, 30), 0xFF385471);
    frame.draw_rect(rect, 0xFF2A3644);
    frame.draw_text(
        rect.x + 13,
        rect.y + 7,
        label(&text.title, 42),
        0xFFFFFFFF,
        None,
    );
    for (index, line) in text.lines.iter().enumerate() {
        frame.draw_text(
            rect.x + 22,
            rect.y + 52 + index as i32 * 25,
            label(line, 40),
            0xFF243645,
            None,
        );
    }

    let button = ok_button(rect);
    frame.fill_rect(button, 0xFFE2EAF2);
    frame.draw_rect(button, 0xFF597893);
    let caption = label(&text.button, 8);
    let caption_x =
        button.x + (button.width as i32 - (caption.len() * super::font::FONT_WIDTH) as i32) / 2;
    frame.draw_text(caption_x, button.y + 4, caption, 0xFF243645, None);
}
