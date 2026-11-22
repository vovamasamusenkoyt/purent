//! NT Kernel Executive Services (Rtl, Io, Mm, Ke, Ob)

pub mod io;
pub mod mm;
pub mod ob;
pub mod zw;

pub use io::*;
pub use mm::*;
pub use ob::*;
pub use zw::*;

use purent_hal::kprintln;
use purent_ntdef::{
    io::{DeviceObject, DriverObject, Irp},
    status::{NtStatus, STATUS_SUCCESS},
    string::UnicodeString,
};

pub const DEVICE_TAG: u32 = 0x65766544; // 'Deve'

#[no_mangle]
pub unsafe extern "win64" fn RtlInitUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const u16,
) {
    if destination_string.is_null() {
        return;
    }
    if source_string.is_null() {
        *destination_string = UnicodeString::empty();
        return;
    }
    let mut len = 0usize;
    while *source_string.add(len) != 0 {
        len += 1;
    }
    let bytes_len = (len * 2) as u16;
    (*destination_string).length = bytes_len;
    (*destination_string).maximum_length = bytes_len + 2;
    (*destination_string).buffer = source_string as *mut u16;
}

#[no_mangle]
pub unsafe extern "win64" fn IoCreateDevice(
    driver_object: *mut DriverObject,
    device_extension_size: u32,
    device_name: *mut UnicodeString,
    device_type: u32,
    device_characteristics: u32,
    _exclusive: u8,
    device_object: *mut *mut DeviceObject,
) -> NtStatus {
    let dev_size = core::mem::size_of::<DeviceObject>();
    let total_size = dev_size + (device_extension_size as usize);

    // Dynamically allocate from NonPagedPool
    let dev_ptr = ExAllocatePoolWithTag(NonPagedPool, total_size, DEVICE_TAG) as *mut DeviceObject;
    if dev_ptr.is_null() {
        return -1073741801; // STATUS_NO_MEMORY
    }

    core::ptr::write_bytes(dev_ptr as *mut u8, 0, total_size);

    (*dev_ptr).r#type = 3; // IO_TYPE_DEVICE
    (*dev_ptr).size = total_size as u16;
    (*dev_ptr).reference_count = 1;
    (*dev_ptr).driver_object = driver_object;
    (*dev_ptr).device_type = device_type;
    (*dev_ptr).characteristics = device_characteristics;
    (*dev_ptr).stack_size = 1;

    if device_extension_size > 0 {
        (*dev_ptr).device_extension = (dev_ptr as usize + dev_size) as *mut core::ffi::c_void;
    }

    if !driver_object.is_null() {
        (*dev_ptr).next_device = (*driver_object).device_object;
        (*driver_object).device_object = dev_ptr;
    }

    if !device_object.is_null() {
        *device_object = dev_ptr;
    }

    if !device_name.is_null() && !(*device_name).buffer.is_null() {
        let u16_slice = core::slice::from_raw_parts((*device_name).buffer, ((*device_name).length / 2) as usize);
        let mut name_buf = [0u8; 64];
        let mut idx = 0;
        for &ch in u16_slice {
            if idx < 63 {
                name_buf[idx] = ch as u8;
                idx += 1;
            }
        }
        let full_name = core::str::from_utf8_unchecked(&name_buf[..idx]);
        if full_name.starts_with("\\Device\\") {
            let short_name = &full_name["\\Device\\".len()..];
            ob_insert_device(dev_ptr as *mut u8, short_name);
        } else if full_name.starts_with("\\FileSystem\\") {
            let short_name = &full_name["\\FileSystem\\".len()..];
            ob_insert_filesystem(dev_ptr as *mut u8, short_name);
        } else {
            ob_insert_device(dev_ptr as *mut u8, full_name);
        }
    } else {
        kprintln!("[IO] IoCreateDevice: anonymous device created at 0x{:p}", dev_ptr);
    }

    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn IoDeleteDevice(device_object: *mut DeviceObject) {
    if !device_object.is_null() {
        kprintln!("[IO] IoDeleteDevice at 0x{:p}", device_object);
        ExFreePoolWithTag(device_object as *mut core::ffi::c_void, DEVICE_TAG);
    }
}

#[no_mangle]
pub unsafe extern "win64" fn IoDeleteSymbolicLink(_symbolic_link_name: *mut UnicodeString) -> NtStatus {
    kprintln!("[IO] IoDeleteSymbolicLink called");
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn IofCompleteRequest(irp: *mut Irp, priority_boost: i8) {
    if !irp.is_null() {
        kprintln!("[IO] IofCompleteRequest: IRP 0x{:p} completed (Status: 0x{:08X}, Info: {}, Boost: {})",
            irp,
            (*irp).io_status.status,
            (*irp).io_status.information,
            priority_boost
        );
    }
}

#[no_mangle]
pub unsafe extern "win64" fn MmPageEntireDriver(address: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    address
}

#[no_mangle]
pub unsafe extern "win64" fn IoRegisterFileSystem(device_object: *mut DeviceObject) {
    kprintln!("[IO] IoRegisterFileSystem: registering filesystem device 0x{:p}", device_object);
}

#[no_mangle]
pub unsafe extern "win64" fn IoUnregisterFileSystem(device_object: *mut DeviceObject) {
    kprintln!("[IO] IoUnregisterFileSystem: unregistering filesystem device 0x{:p}", device_object);
}

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
