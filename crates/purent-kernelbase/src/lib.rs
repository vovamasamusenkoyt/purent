//! Library-loader APIs for the built-in Win32 modules.

#![no_std]
#![allow(non_snake_case)]

#[path = "../../purent-ntdef/src/freestanding.rs"]
mod freestanding;

use purent_ntdef::string::{AnsiString, UnicodeString};
use purent_ntdef::syscall::nt_current_peb_address;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn LdrGetDllHandle(
        path: *const u16,
        characteristics: *const u32,
        name: *const UnicodeString,
        result: *mut usize,
    ) -> i32;
    fn LdrLoadDll(
        path: *const u16,
        characteristics: *const u32,
        name: *const UnicodeString,
        result: *mut usize,
    ) -> i32;
    fn LdrGetProcedureAddress(
        module: usize,
        name: *const AnsiString,
        ordinal: u32,
        result: *mut usize,
    ) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "system" fn DllMain(_: usize, _: u32, _: usize) -> i32 {
    1
}

unsafe fn module_name(name: *const u16) -> Option<UnicodeString> {
    if name.is_null() {
        return None;
    }
    for len in 0..64 {
        if *name.add(len) == 0 {
            return Some(UnicodeString::from_raw_parts(
                name.cast_mut(),
                (len * 2) as u16,
                ((len + 1) * 2) as u16,
            ));
        }
    }
    None
}

#[no_mangle]
pub unsafe extern "win64" fn GetModuleHandleW(name: *const u16) -> usize {
    if name.is_null() {
        return (*(nt_current_peb_address() as *const purent_ntdef::ps::Peb)).image_base_address
            as usize;
    }
    let Some(name) = module_name(name) else {
        return 0;
    };
    let mut result = 0;
    LdrGetDllHandle(core::ptr::null(), core::ptr::null(), &name, &mut result);
    result
}

#[no_mangle]
pub unsafe extern "win64" fn GetProcAddress(module: usize, proc_name: *const u8) -> usize {
    if proc_name as usize <= u16::MAX as usize {
        return 0;
    }
    for len in 0..256 {
        if *proc_name.add(len) == 0 {
            let name = AnsiString {
                length: len as u16,
                maximum_length: len as u16 + 1,
                buffer: proc_name.cast_mut(),
            };
            let mut result = 0;
            LdrGetProcedureAddress(module, &name, 0, &mut result);
            return result;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn LoadLibraryExW(name: *const u16, file: usize, flags: u32) -> usize {
    if file != 0 || flags != 0 {
        return 0;
    }
    let Some(name) = module_name(name) else {
        return 0;
    };
    let mut result = 0;
    LdrLoadDll(core::ptr::null(), core::ptr::null(), &name, &mut result);
    result
}
