//! PureNT Clean-Room Window Management Subsystem
//! Window frame rendering, non-client area calculation, and Z-order dispatch matching Windows 7 SP1 Aero

use super::{surface::{Rect, Surface}, ui_font::LABEL};

pub const BORDER_LEFT: u32 = 10;
pub const BORDER_RIGHT: u32 = 10;
pub const BORDER_BOTTOM: u32 = 10;
pub const CAPTION_HEIGHT: u32 = 32;

const BUTTON_INSET: i32 = 9;
const BUTTON_WIDTH: u32 = 39;
const BUTTON_HEIGHT: u32 = 21;
const BUTTON_GAP: i32 = 3;

#[derive(Clone, Copy)]
pub enum FrameControls {
    Close,
    Console,
}

#[derive(Clone, Copy)]
pub struct NonClient {
    pub frame: Rect,
    pub client: Rect,
    pub controls: FrameControls,
}

impl NonClient {
    pub fn caption(self) -> Rect {
        Rect::new(self.frame.x, self.frame.y, self.frame.width, (self.client.y - self.frame.y) as u32)
    }

    pub fn close_button(self) -> Rect {
        Rect::new(self.frame.right() - BUTTON_INSET - BUTTON_WIDTH as i32,
            self.frame.y + 6, BUTTON_WIDTH, BUTTON_HEIGHT)
    }

    fn auxiliary_buttons(self) -> [Rect; 2] {
        let close = self.close_button();
        let width = 24;
        let nearest = close.x - BUTTON_GAP - width as i32;
        [
            Rect::new(nearest - BUTTON_GAP - width as i32, close.y, width, close.height),
            Rect::new(nearest, close.y, width, close.height),
        ]
    }

    pub fn draw(
        self, surface: &mut Surface, title: &str, title_inset: i32, redirected: bool, active: bool,
    ) {
        let frame = self.frame;
        let client = self.client;
        let tint = match (redirected, active) {
            (true, true) => 0x28447CAF,
            (true, false) => 0x305C6975,
            (false, true) => 0xFF98B7D1,
            (false, false) => 0xFFA7B6C3,
        };
        for strip in [
            self.caption(),
            Rect::new(frame.x, client.y, (client.x - frame.x) as u32, client.height),
            Rect::new(client.right(), client.y, (frame.right() - client.right()) as u32, client.height),
            Rect::new(frame.x, client.bottom(), frame.width, (frame.bottom() - client.bottom()) as u32),
        ] {
            surface.fill_rect(strip, tint);
        }
        surface.draw_rect(frame, 0xFF304962);
        let highlight = if redirected { 0xA6EEF7FF } else { 0xFFE1EAF3 };
        surface.draw_rect(Rect::new(frame.x + 1, frame.y + 1, frame.width - 2, frame.height - 2), highlight);
        surface.draw_rect(Rect::new(client.x - 1, client.y - 1, client.width + 2, client.height + 2), 0xFF576F87);
        LABEL.draw(surface, frame.x + title_inset, frame.y + 6, title, 0xFF182D43);

        let close = self.close_button();
        let (top, bottom) = if active { (0xFFC66B63, 0xFF9D4549) } else { (0xFFA67A77, 0xFF805C62) };
        surface.draw_gradient_v(close, top, bottom);
        surface.draw_rect(close, 0xFF703C46);
        surface.fill_rect(Rect::new(close.x + 1, close.y + 1, close.width - 2, 1), 0xFFE4AAA2);
        for offset in 0..7 {
            surface.put_pixel(close.x + 16 + offset, close.y + 7 + offset, 0xFFFFF8F4);
            surface.put_pixel(close.x + 22 - offset, close.y + 7 + offset, 0xFFFFF8F4);
        }

        if matches!(self.controls, FrameControls::Console) {
            let [minimize, maximize] = self.auxiliary_buttons();
            for button in [minimize, maximize] {
                surface.draw_gradient_v(button, 0xFFF4F8FC, 0xFFB6CBDD);
                surface.draw_rect(button, 0xFF617991);
            }
            surface.fill_rect(Rect::new(minimize.x + 8, minimize.y + 13, 8, 1), 0xFF273F56);
            surface.draw_rect(Rect::new(maximize.x + 8, maximize.y + 7, 8, 7), 0xFF273F56);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaptionHit {
    Outside,
    Caption,
    Buttons,
    Close,
}

static CMD_ICON_16X16: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/theme/cmd_icon_16x16.raw"));

#[derive(Clone, Copy)]
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
            self.rect.x + BORDER_LEFT as i32,
            self.rect.y + CAPTION_HEIGHT as i32,
            self.rect.width.saturating_sub(BORDER_LEFT + BORDER_RIGHT),
            self.rect.height.saturating_sub(CAPTION_HEIGHT + BORDER_BOTTOM),
        )
    }

    pub fn non_client(&self) -> NonClient {
        NonClient { frame: self.rect, client: self.client_rect(), controls: FrameControls::Console }
    }

    pub fn hit_test_caption(&self, x: i32, y: i32) -> CaptionHit {
        let chrome = self.non_client();
        if chrome.close_button().contains(x, y) {
            CaptionHit::Close
        } else if chrome.auxiliary_buttons().iter().any(|button| button.contains(x, y)) {
            CaptionHit::Buttons
        } else if !self.is_minimized && chrome.caption().contains(x, y) {
            CaptionHit::Caption
        } else {
            CaptionHit::Outside
        }
    }

    pub fn draw_chrome(&self, surface: &mut Surface, redirected: bool) {
        self.non_client().draw(surface, self.title, 32, redirected, self.is_active);
        surface.blit_raw_rgba(self.rect.x + 10, self.rect.y + 8, 16, 16, CMD_ICON_16X16);
    }
}
