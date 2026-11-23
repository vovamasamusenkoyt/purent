use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};

use purent_ntdef::{
    composition::MAX_WINDOW_SURFACES,
    syscall::{nt_current_teb_address, nt_syscall4, SYSCALL_PURENT_WINDOW},
    window::*,
};

const ATOM_BASE: usize = 0xC000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;

#[repr(C)]
struct CreateStruct {
    parameter: *mut c_void,
    instance: usize,
    menu: usize,
    parent: usize,
    height: i32,
    width: i32,
    y: i32,
    x: i32,
    style: i32,
    title: *const u16,
    class_name: *const u16,
    ex_style: u32,
}

#[derive(Clone, Copy)]
struct Class {
    name: [u16; 64],
    instance: usize,
    procedure: WindowProcedure,
}

#[derive(Clone, Copy)]
struct Window {
    handle: usize,
    procedure: WindowProcedure,
    thread: usize,
    destroying: bool,
}

struct Registry {
    classes: [Option<Class>; 8],
    windows: [Option<Window>; MAX_WINDOW_SURFACES],
}

static BUSY: AtomicBool = AtomicBool::new(false);
static mut REGISTRY: Registry = Registry {
    classes: [None; 8],
    windows: [None; MAX_WINDOW_SURFACES],
};

fn registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    while BUSY.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let result = unsafe { f(&mut *(&raw mut REGISTRY)) };
    BUSY.store(false, Ordering::Release);
    result
}

unsafe fn read_text(ptr: *const u16) -> [u16; 64] {
    let mut text = [0; 64];
    if !ptr.is_null() {
        for (index, out) in text[..63].iter_mut().enumerate() {
            let unit = ptr.add(index).read();
            if unit == 0 {
                break;
            }
            *out = unit;
        }
    }
    text
}

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.iter().zip(right).all(|(&a, &b)| {
        a == b || matches!((u8::try_from(a), u8::try_from(b)), (Ok(a), Ok(b)) if a.eq_ignore_ascii_case(&b))
    })
}

unsafe fn call(operation: u64, hwnd: usize, arg: usize, extra: usize) -> i32 {
    nt_syscall4(
        SYSCALL_PURENT_WINDOW,
        operation,
        hwnd as u64,
        arg as u64,
        extra as u64,
    )
}

#[no_mangle]
pub unsafe extern "system" fn RegisterClassExW(input: *const WindowClass) -> u16 {
    let Some(input) = input.as_ref() else {
        return 0;
    };
    if input.size as usize != core::mem::size_of::<WindowClass>() {
        return 0;
    }
    let Some(procedure) = input.procedure else {
        return 0;
    };
    let name = read_text(input.class_name);
    if name[0] == 0 {
        return 0;
    }
    registry(|registry| {
        if registry
            .classes
            .iter()
            .flatten()
            .any(|class| class.instance == input.instance && same_name(&class.name, &name))
        {
            return 0;
        }
        let Some(index) = registry.classes.iter().position(Option::is_none) else {
            return 0;
        };
        registry.classes[index] = Some(Class {
            name,
            instance: input.instance,
            procedure,
        });
        (ATOM_BASE + index) as u16
    })
}

#[no_mangle]
pub unsafe extern "system" fn CreateWindowExW(
    ex_style: u32,
    class_name: *const u16,
    title: *const u16,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: usize,
    menu: usize,
    instance: usize,
    parameter: *mut c_void,
) -> usize {
    if class_name.is_null() || style & WS_CHILD != 0 || parent != 0 || menu != 0 {
        return 0;
    }
    let class_value = class_name as usize;
    let name = (class_value > u16::MAX as usize).then(|| read_text(class_name));
    let procedure = registry(|registry| {
        if let Some(name) = name {
            registry
                .classes
                .iter()
                .flatten()
                .find(|class| class.instance == instance && same_name(&class.name, &name))
                .map(|class| class.procedure)
        } else {
            let index = class_value.checked_sub(ATOM_BASE)?;
            registry
                .classes
                .get(index)?
                .filter(|class| class.instance == instance)
                .map(|class| class.procedure)
        }
    });
    let Some(procedure) = procedure else { return 0 };
    let request = WindowCreate {
        x,
        y,
        width,
        height,
        title: read_text(title),
    };
    let handle = call(CREATE, 0, &request as *const _ as usize, 0);
    if handle <= 0 {
        return 0;
    }
    let hwnd = handle as usize;
    let registered = registry(|registry| {
        if let Some(slot) = registry.windows.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(Window {
                handle: hwnd,
                procedure,
                thread: nt_current_teb_address(),
                destroying: false,
            });
            true
        } else {
            false
        }
    });
    if !registered {
        call(DESTROY, hwnd, 0, 0);
        return 0;
    }
    let create = CreateStruct {
        parameter,
        instance,
        menu,
        parent,
        height,
        width,
        y,
        x,
        style: style as i32,
        title,
        class_name,
        ex_style,
    };
    let lparam = &create as *const _ as isize;
    if procedure(hwnd, WM_NCCREATE, 0, lparam) == 0 {
        procedure(hwnd, WM_NCDESTROY, 0, 0);
        release_window(hwnd);
        return 0;
    }
    if procedure(hwnd, WM_CREATE, 0, lparam) == -1 {
        DestroyWindow(hwnd);
        return 0;
    }
    if !registry(|registry| {
        registry
            .windows
            .iter()
            .flatten()
            .any(|window| window.handle == hwnd)
    }) {
        return 0;
    }
    if style & WS_VISIBLE != 0 {
        ShowWindow(hwnd, 5);
    }
    hwnd
}

unsafe fn release_window(hwnd: usize) -> i32 {
    let status = call(DESTROY, hwnd, 0, 0);
    registry(|registry| {
        if let Some(slot) = registry
            .windows
            .iter_mut()
            .find(|slot| slot.is_some_and(|window| window.handle == hwnd))
        {
            if status == 0 {
                *slot = None;
            } else if let Some(window) = slot {
                window.destroying = false;
            }
        }
    });
    i32::from(status == 0)
}

#[no_mangle]
pub unsafe extern "system" fn ShowWindow(hwnd: usize, command: i32) -> i32 {
    call(SHOW, hwnd, usize::from(command != 0), 0).max(0)
}

#[no_mangle]
pub unsafe extern "system" fn DestroyWindow(hwnd: usize) -> i32 {
    let procedure = registry(|registry| {
        let window = registry.windows.iter_mut().flatten().find(|window| {
            window.handle == hwnd && window.thread == nt_current_teb_address() && !window.destroying
        })?;
        window.destroying = true;
        Some(window.procedure)
    });
    let Some(procedure) = procedure else { return 0 };
    procedure(hwnd, WM_DESTROY, 0, 0);
    procedure(hwnd, WM_NCDESTROY, 0, 0);
    release_window(hwnd)
}

#[no_mangle]
pub unsafe extern "system" fn GetMessageW(
    message: *mut Message,
    hwnd: usize,
    min: u32,
    max: u32,
) -> i32 {
    // This message loop supports unfiltered reads from the calling thread.
    if hwnd != 0 || min != 0 || max != 0 {
        return -1;
    }
    let result = call(GET_MESSAGE, 0, message as usize, 0);
    if result < 0 {
        -1
    } else {
        result
    }
}

#[no_mangle]
pub unsafe extern "system" fn DispatchMessageW(message: *const Message) -> isize {
    let Some(message) = message.as_ref() else {
        return 0;
    };
    let procedure = registry(|registry| {
        registry
            .windows
            .iter()
            .flatten()
            .find(|window| {
                window.handle == message.hwnd && window.thread == nt_current_teb_address()
            })
            .map(|window| window.procedure)
    });
    procedure.map_or(0, |proc| {
        proc(
            message.hwnd,
            message.message,
            message.wparam,
            message.lparam,
        )
    })
}

#[no_mangle]
pub unsafe extern "system" fn DefWindowProcW(
    hwnd: usize,
    message: u32,
    _: usize,
    _: isize,
) -> isize {
    match message {
        WM_NCCREATE => 1,
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_PAINT => {
            let mut paint = core::mem::MaybeUninit::<PaintStruct>::uninit();
            if BeginPaint(hwnd, paint.as_mut_ptr()) != 0 {
                EndPaint(hwnd, paint.as_ptr());
            }
            0
        }
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "system" fn PostQuitMessage(code: i32) {
    call(POST_QUIT, 0, code as usize, 0);
}

#[no_mangle]
pub unsafe extern "system" fn InvalidateRect(hwnd: usize, rect: *const Rect, erase: i32) -> i32 {
    i32::from(call(INVALIDATE, hwnd, rect as usize, usize::from(erase != 0)) == 0)
}

#[no_mangle]
pub unsafe extern "system" fn BeginPaint(hwnd: usize, paint: *mut PaintStruct) -> usize {
    if call(BEGIN_PAINT, hwnd, paint as usize, 0) == 0 {
        hwnd
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "system" fn EndPaint(hwnd: usize, paint: *const PaintStruct) -> i32 {
    if paint.is_null() || (*paint).dc != hwnd {
        return 0;
    }
    i32::from(call(END_PAINT, hwnd, 0, 0) == 0)
}

#[no_mangle]
pub extern "system" fn GetSysColorBrush(index: i32) -> usize {
    if system_color(index).is_some() {
        index as usize + 1
    } else {
        0
    }
}

fn system_color(index: i32) -> Option<u32> {
    match index {
        5 => Some(0xF5F8FC),  // COLOR_WINDOW
        13 => Some(0x4278A8), // COLOR_HIGHLIGHT
        15 => Some(0xDCE7EF), // COLOR_BTNFACE
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "system" fn FillRect(dc: usize, rect: *const Rect, brush: usize) -> i32 {
    let color = brush
        .checked_sub(1)
        .and_then(|index| i32::try_from(index).ok())
        .and_then(system_color);
    let Some(color) = color else { return 0 };
    i32::from(call(FILL_RECT, dc, rect as usize, color as usize) == 0)
}
