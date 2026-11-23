#![no_std]
#![no_main]

use core::{
    ffi::c_void,
    mem::MaybeUninit,
    ptr::{null, null_mut},
};
use purent_ntdef::window::*;

#[path = "../../../purent-ntdef/src/freestanding.rs"]
mod freestanding;

#[link(name = "user32", kind = "raw-dylib")]
extern "system" {
    fn RegisterClassExW(class: *const WindowClass) -> u16;
    fn CreateWindowExW(
        ex_style: u32,
        class_name: *const u16,
        name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: usize,
        menu: usize,
        instance: usize,
        parameter: *mut c_void,
    ) -> usize;
    fn ShowWindow(hwnd: usize, cmd: i32) -> i32;
    fn GetMessageW(message: *mut Message, hwnd: usize, min: u32, max: u32) -> i32;
    fn DispatchMessageW(message: *const Message) -> isize;
    fn DefWindowProcW(hwnd: usize, message: u32, wparam: usize, lparam: isize) -> isize;
    fn PostQuitMessage(code: i32);
    fn BeginPaint(hwnd: usize, paint: *mut PaintStruct) -> usize;
    fn EndPaint(hwnd: usize, paint: *const PaintStruct) -> i32;
    fn FillRect(dc: usize, rect: *const Rect, brush: usize) -> i32;
    fn GetSysColorBrush(index: i32) -> usize;
}

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> usize;
    fn WriteFile(
        file: usize,
        bytes: *const u8,
        size: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

static mut FIRST: usize = 0;
static mut REMAINING: u32 = 0;

const fn wide<const N: usize>(ascii: &[u8; N]) -> [u16; N] {
    let mut text = [0; N];
    let mut i = 0;
    while i < N {
        text[i] = ascii[i] as u16;
        i += 1;
    }
    text
}

unsafe fn log(first: bool, message: u32) {
    let text: &[u8] = match (first, message) {
        (true, WM_PAINT) => b"[windowdemo] 1 WM_PAINT\n",
        (false, WM_PAINT) => b"[windowdemo] 2 WM_PAINT\n",
        (true, WM_SETFOCUS) => b"[windowdemo] 1 WM_SETFOCUS\n",
        (false, WM_SETFOCUS) => b"[windowdemo] 2 WM_SETFOCUS\n",
        (true, WM_CLOSE) => b"[windowdemo] 1 WM_CLOSE\n",
        (false, WM_CLOSE) => b"[windowdemo] 2 WM_CLOSE\n",
        _ => return,
    };
    WriteFile(4, text.as_ptr(), text.len() as u32, null_mut(), 0);
}

unsafe extern "system" fn window_proc(
    hwnd: usize,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let first = hwnd == FIRST;
    match message {
        WM_PAINT => {
            let mut paint = MaybeUninit::<PaintStruct>::uninit();
            let dc = BeginPaint(hwnd, paint.as_mut_ptr());
            if dc != 0 {
                let paint = paint.assume_init();
                let color = if first { 13 } else { 15 };
                FillRect(dc, &paint.paint, GetSysColorBrush(color));
                let inset = Rect {
                    left: 22,
                    top: 22,
                    right: paint.paint.right - 22,
                    bottom: paint.paint.bottom - 22,
                };
                FillRect(dc, &inset, GetSysColorBrush(5));
                if EndPaint(hwnd, &paint) != 0 {
                    log(first, message);
                }
            }
            0
        }
        WM_SETFOCUS | WM_CLOSE => {
            log(first, message);
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        WM_DESTROY => {
            REMAINING -= 1;
            if REMAINING == 0 {
                PostQuitMessage(0);
            }
            0
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

#[no_mangle]
pub unsafe extern "system" fn main() -> i32 {
    let msg = b"[windowdemo] main entered!\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
    let instance = GetModuleHandleW(null());
    let msg = b"[windowdemo] got instance\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
    let class_name = wide(b"PureNtWindowDemo\0");
    let class = WindowClass {
        size: core::mem::size_of::<WindowClass>() as u32,
        style: 0,
        procedure: Some(window_proc),
        class_extra: 0,
        window_extra: 0,
        instance,
        icon: 0,
        cursor: 0,
        background: 0,
        menu_name: null(),
        class_name: class_name.as_ptr(),
        small_icon: 0,
    };
    let reg_res = RegisterClassExW(&class);
    if reg_res == 0 {
        let msg = b"[windowdemo] RegisterClassExW FAILED\n";
        WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
        return 1;
    }
    let msg = b"[windowdemo] class registered\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);

    let first = CreateWindowExW(
        0,
        class_name.as_ptr(),
        wide(b"Window demo - 1\0").as_ptr(),
        0x00CF_0000,
        170,
        135,
        410,
        255,
        0,
        0,
        instance,
        null_mut(),
    );
    let msg = b"[windowdemo] window 1 created\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
    let second = CreateWindowExW(
        0,
        class_name.as_ptr(),
        wide(b"Window demo - 2\0").as_ptr(),
        0x00CF_0000,
        400,
        230,
        410,
        255,
        0,
        0,
        instance,
        null_mut(),
    );
    let msg = b"[windowdemo] window 2 created\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
    if first == 0 || second == 0 {
        let msg = b"[windowdemo] CreateWindow FAILED\n";
        WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);
        return 2;
    }
    FIRST = first;
    REMAINING = 2;
    ShowWindow(first, 5);
    ShowWindow(second, 5);
    let msg = b"[windowdemo] windows shown, entering loop\n";
    WriteFile(4, msg.as_ptr(), msg.len() as u32, null_mut(), 0);

    let mut msg = Message::default();
    loop {
        match GetMessageW(&mut msg, 0, 0, 0) {
            -1 => return 3,
            0 => return msg.wparam as i32,
            _ => {
                DispatchMessageW(&msg);
            }
        }
    }
}
