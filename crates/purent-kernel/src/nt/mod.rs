//! NT Kernel Executive Services (Rtl, Io, Mm, Ke)

use purent_hal::kprintln;
use purent_ntdef::{
    string::UnicodeString,
    status::{NtStatus, STATUS_SUCCESS},
    io::{DriverObject, DeviceObject, Irp},
};

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

static mut CREATED_DEVICES: [DeviceObject; 8] = [DeviceObject {
    r#type: 3,
    size: core::mem::size_of::<DeviceObject>() as u16,
    reference_count: 1,
    driver_object: core::ptr::null_mut(),
    next_device: core::ptr::null_mut(),
    attached_device: core::ptr::null_mut(),
    current_irp: core::ptr::null_mut(),
    timer: core::ptr::null_mut(),
    flags: 0,
    characteristics: 0,
    vpb: core::ptr::null_mut(),
    device_extension: core::ptr::null_mut(),
    device_type: 0,
    stack_size: 1,
}; 8];
static mut CREATED_DEVICE_COUNT: usize = 0;

#[no_mangle]
pub unsafe extern "win64" fn IoCreateDevice(
    driver_object: *mut DriverObject,
    _device_extension_size: u32,
    device_name: *mut UnicodeString,
    device_type: u32,
    device_characteristics: u32,
    _exclusive: u8,
    device_object: *mut *mut DeviceObject,
) -> NtStatus {
    if CREATED_DEVICE_COUNT >= CREATED_DEVICES.len() {
        return -1073741801; // STATUS_NO_MEMORY
    }

    let dev_ptr = &raw mut CREATED_DEVICES[CREATED_DEVICE_COUNT];
    CREATED_DEVICE_COUNT += 1;

    (*dev_ptr).driver_object = driver_object;
    (*dev_ptr).device_type = device_type;
    (*dev_ptr).characteristics = device_characteristics;
    (*dev_ptr).stack_size = 1;

    if !driver_object.is_null() {
        (*dev_ptr).next_device = (*driver_object).device_object;
        (*driver_object).device_object = dev_ptr;
    }

    if !device_object.is_null() {
        *device_object = dev_ptr;
    }

    if !device_name.is_null() && !(*device_name).buffer.is_null() {
        kprintln!("[IO] IoCreateDevice: registered device type 0x{:X}", device_type);
    } else {
        kprintln!("[IO] IoCreateDevice: anonymous device created");
    }

    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn IoDeleteDevice(device_object: *mut DeviceObject) {
    kprintln!("[IO] IoDeleteDevice at 0x{:p}", device_object);
}

#[no_mangle]
pub unsafe extern "win64" fn IoDeleteSymbolicLink(_symbolic_link_name: *mut UnicodeString) -> NtStatus {
    kprintln!("[IO] IoDeleteSymbolicLink called");
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn IofCompleteRequest(irp: *mut Irp, priority_boost: i8) {
    kprintln!("[IO] IofCompleteRequest: IRP at 0x{:p} completed (boost: {})", irp, priority_boost);
}

#[no_mangle]
pub unsafe extern "win64" fn MmPageEntireDriver(address: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    // PureNT runs resident drivers in kernel space
    address
}

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
