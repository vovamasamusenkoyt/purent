//! NT I/O Driver Dispatching Engine

use purent_hal::kprintln;
use purent_ntdef::{
    io::{DeviceObject, Irp},
    status::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED},
};

use super::irp::io_get_current_irp_stack_location;

#[no_mangle]
pub unsafe extern "win64" fn IoCallDriver(
    device_object: *mut DeviceObject,
    irp: *mut Irp,
) -> NtStatus {
    if device_object.is_null() || irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Advance stack location
    (*irp).current_location -= 1;
    if (*irp).current_location <= 0 {
        kprintln!("[IO] FATAL: IRP stack location underflow!");
        return STATUS_INVALID_PARAMETER;
    }

    let stack = io_get_current_irp_stack_location(irp);
    (*irp).current_stack_location = stack;
    (*stack).device_object = device_object;

    let driver_object = (*device_object).driver_object;
    if driver_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let major_fn = (*stack).major_function as usize;
    if major_fn >= (*driver_object).major_function.len() {
        return STATUS_NOT_SUPPORTED;
    }

    let routine_ptr = (*driver_object).major_function[major_fn];
    if routine_ptr.is_null() {
        kprintln!("[IO] Major function 0x{:X} not implemented by driver", major_fn);
        return STATUS_NOT_SUPPORTED;
    }

    let dispatch_routine: unsafe extern "win64" fn(*mut DeviceObject, *mut Irp) -> NtStatus =
        core::mem::transmute(routine_ptr);

    dispatch_routine(device_object, irp)
}

#[no_mangle]
pub unsafe extern "win64" fn IofCallDriver(device_object: *mut DeviceObject, irp: *mut Irp) -> NtStatus {
    IoCallDriver(device_object, irp)
}
