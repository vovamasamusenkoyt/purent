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
    if (*irp).current_location <= 1 {
        kprintln!("[IO] FATAL: IRP stack location underflow!");
        return STATUS_INVALID_PARAMETER;
    }

    (*irp).current_location -= 1;
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

/// Dispatch a caller-owned IRP and collect its final status before freeing it.
pub unsafe fn io_call_driver_sync(
    device: *mut DeviceObject,
    irp: *mut Irp,
) -> purent_ntdef::io::IoStatusBlock {
    use crate::ke::{KeInitializeEvent, KeWaitForSingleObject, KernelEvent};
    use purent_ntdef::{io::IoStatusBlock, status::STATUS_PENDING};

    let mut event = core::mem::MaybeUninit::<KernelEvent>::uninit();
    let event_ptr = event.as_mut_ptr().cast();
    KeInitializeEvent(event_ptr, 0, 0);
    let mut iosb = IoStatusBlock { status: STATUS_PENDING, information: 0 };
    (*irp).user_event = event_ptr;
    (*irp).user_iosb = (&raw mut iosb).cast();
    let dispatched = IoCallDriver(device, irp);
    if dispatched == STATUS_PENDING {
        let status = KeWaitForSingleObject(event_ptr, 0, 0, 0, core::ptr::null_mut());
        debug_assert_eq!(status, 0);
    } else if !event.assume_init_ref().is_signaled() {
        iosb = IoStatusBlock { status: dispatched, information: (*irp).io_status.information };
    }
    super::irp::IoFreeIrp(irp);
    iosb
}
