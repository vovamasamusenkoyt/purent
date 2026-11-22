//! NT I/O Request Packet (IRP) Allocation and Construction

use purent_ntdef::io::{DeviceObject, IoStackLocation, IoStatusBlock, Irp, IRP_MJ_DEVICE_CONTROL};
use crate::mm::{ExAllocatePoolWithTag, ExFreePoolWithTag, NonPagedPool};

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
    (*ptr).current_stack_location = io_get_stack_location_ptr(ptr, stack_size as usize);

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
pub unsafe extern "win64" fn IoBuildDeviceIoControlRequest(
    io_control_code: u32,
    device_object: *mut DeviceObject,
    _input_buffer: *mut core::ffi::c_void,
    input_buffer_length: u32,
    output_buffer: *mut core::ffi::c_void,
    output_buffer_length: u32,
    _internal_device_io_control: u8,
    _event: *mut core::ffi::c_void,
    _io_status_block: *mut IoStatusBlock,
) -> *mut Irp {
    let stack_size = if !device_object.is_null() {
        (*device_object).stack_size.max(1)
    } else {
        1
    };
    let irp = IoAllocateIrp(stack_size, 0);
    if !irp.is_null() {
        (*irp).user_buffer = output_buffer;
        let stack = io_get_next_irp_stack_location(irp);
        (*stack).major_function = IRP_MJ_DEVICE_CONTROL;
        (*stack).device_object = device_object;
        (*stack).parameters[0] = output_buffer_length as usize;
        (*stack).parameters[1] = input_buffer_length as usize;
        (*stack).parameters[2] = io_control_code as usize;
    }
    irp
}

#[no_mangle]
pub unsafe extern "win64" fn IoBuildSynchronousFsdRequest(
    major_function: u32,
    device_object: *mut DeviceObject,
    buffer: *mut core::ffi::c_void,
    length: u32,
    _starting_offset: *mut i64,
    _event: *mut core::ffi::c_void,
    _io_status_block: *mut IoStatusBlock,
) -> *mut Irp {
    let stack_size = if !device_object.is_null() {
        (*device_object).stack_size.max(1)
    } else {
        1
    };
    let irp = IoAllocateIrp(stack_size, 0);
    if !irp.is_null() {
        (*irp).user_buffer = buffer;
        let stack = io_get_next_irp_stack_location(irp);
        (*stack).major_function = major_function as u8;
        (*stack).device_object = device_object;
        (*stack).parameters[0] = length as usize;
    }
    irp
}
