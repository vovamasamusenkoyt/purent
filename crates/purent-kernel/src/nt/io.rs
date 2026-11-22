//! NT I/O Subsystem & IRP Dispatch Engine

use purent_hal::kprintln;
use purent_ntdef::{
    io::{DeviceObject, IoStackLocation, Irp},
    status::{NtStatus, STATUS_NOT_SUPPORTED},
};
use crate::nt::mm::{ExAllocatePoolWithTag, ExFreePoolWithTag, NonPagedPool};

pub const IRP_TAG: u32 = 0x20707249; // 'Irp '

#[no_mangle]
pub unsafe extern "win64" fn IoAllocateIrp(stack_size: i8, _charge_quota: u8) -> *mut Irp {
    let irp_base_size = core::mem::size_of::<Irp>();
    let stack_location_size = core::mem::size_of::<IoStackLocation>();
    let total_size = irp_base_size + (stack_size as usize) * stack_location_size;

    let ptr = ExAllocatePoolWithTag(NonPagedPool, total_size, IRP_TAG) as *mut Irp;
    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    core::ptr::write_bytes(ptr as *mut u8, 0, total_size);

    (*ptr).r#type = 6; // IO_TYPE_IRP
    (*ptr).size = total_size as u16;
    (*ptr).stack_count = stack_size;
    (*ptr).current_location = stack_size + 1;

    ptr
}

#[no_mangle]
pub unsafe extern "win64" fn IoFreeIrp(irp: *mut Irp) {
    if !irp.is_null() {
        ExFreePoolWithTag(irp as *mut core::ffi::c_void, IRP_TAG);
    }
}

#[inline(always)]
pub unsafe fn io_get_stack_location_ptr(irp: *mut Irp, index: usize) -> *mut IoStackLocation {
    let irp_base_size = core::mem::size_of::<Irp>();
    let stack_location_size = core::mem::size_of::<IoStackLocation>();
    let ptr = (irp as usize + irp_base_size + index * stack_location_size) as *mut IoStackLocation;
    ptr
}

#[inline(always)]
pub unsafe fn io_get_next_irp_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    let next_index = ((*irp).current_location - 2) as usize;
    io_get_stack_location_ptr(irp, next_index)
}

#[inline(always)]
pub unsafe fn io_get_current_irp_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    let curr_index = ((*irp).current_location - 1) as usize;
    io_get_stack_location_ptr(irp, curr_index)
}

#[no_mangle]
pub unsafe extern "win64" fn IoCallDriver(
    device_object: *mut DeviceObject,
    irp: *mut Irp,
) -> NtStatus {
    if device_object.is_null() || irp.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // Advance stack location
    (*irp).current_location -= 1;
    if (*irp).current_location <= 0 {
        kprintln!("[IO] FATAL: IRP stack location underflow!");
        return -1073741811;
    }

    let stack = io_get_current_irp_stack_location(irp);
    (*stack).device_object = device_object;

    let driver_object = (*device_object).driver_object;
    if driver_object.is_null() {
        return -1073741811;
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
