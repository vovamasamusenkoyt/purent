//! NT Kernel Synchronization Primitives and Bug Check

use purent_hal::kprintln;
use purent_ntdef::status::{NtStatus, STATUS_SUCCESS};

#[no_mangle]
pub unsafe extern "win64" fn KeInitializeEvent(
    event: *mut core::ffi::c_void,
    _event_type: u32,
    initial_state: u8,
) {
    if !event.is_null() {
        core::ptr::write_bytes(event as *mut u8, 0, 24);
        let state_ptr = event as *mut u32;
        *state_ptr = initial_state as u32;
    }
}

#[no_mangle]
pub unsafe extern "win64" fn KeSetEvent(
    event: *mut core::ffi::c_void,
    _increment: i32,
    _wait: u8,
) -> i32 {
    if !event.is_null() {
        let state_ptr = event as *mut u32;
        let prev = *state_ptr;
        *state_ptr = 1;
        prev as i32
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "win64" fn KeWaitForSingleObject(
    _object: *mut core::ffi::c_void,
    _wait_reason: u32,
    _wait_mode: i8,
    _alertable: u8,
    _timeout: *mut i64,
) -> NtStatus {
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn KeEnterCriticalRegion() {}

#[no_mangle]
pub unsafe extern "win64" fn KeLeaveCriticalRegion() {}

#[no_mangle]
pub unsafe extern "win64" fn KeBugCheckEx(
    bug_check_code: u32,
    p1: usize,
    p2: usize,
    p3: usize,
    p4: usize,
) -> ! {
    kprintln!("\n*** STOP: 0x{:08X} (0x{:X}, 0x{:X}, 0x{:X}, 0x{:X})", bug_check_code, p1, p2, p3, p4);
    purent_hal::hlt_loop();
}
