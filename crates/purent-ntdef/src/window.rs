//! Win32 window message and paint structures shared with USER32.

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;

pub type WindowProcedure = unsafe extern "system" fn(usize, u32, usize, isize) -> isize;

#[repr(C)]
pub struct WindowClass {
    pub size: u32,
    pub style: u32,
    pub procedure: Option<WindowProcedure>,
    pub class_extra: i32,
    pub window_extra: i32,
    pub instance: usize,
    pub icon: usize,
    pub cursor: usize,
    pub background: usize,
    pub menu_name: *const u16,
    pub class_name: *const u16,
    pub small_icon: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Message {
    pub hwnd: usize,
    pub message: u32,
    pub wparam: usize,
    pub lparam: isize,
    pub time: u32,
    pub x: i32,
    pub y: i32,
    pub private: u32,
}

#[repr(C)]
pub struct PaintStruct {
    pub dc: usize,
    pub erase: i32,
    pub paint: Rect,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WindowCreate {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub title: [u16; 64],
}

pub const CREATE: u64 = 0;
pub const SHOW: u64 = 1;
pub const DESTROY: u64 = 2;
pub const GET_MESSAGE: u64 = 3;
pub const POST_QUIT: u64 = 4;
pub const BEGIN_PAINT: u64 = 5;
pub const END_PAINT: u64 = 6;
pub const FILL_RECT: u64 = 7;
pub const INVALIDATE: u64 = 8;
