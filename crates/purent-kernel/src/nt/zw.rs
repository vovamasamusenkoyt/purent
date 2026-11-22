//! NT System Calls and Executive API (Zw* / Nt*)
//! Provides native system services that bridge userland and drivers to the kernel I/O and Object systems.

use purent_hal::kprintln;
use purent_ntdef::{
    io::{
        DeviceObject, FileObject, IoStatusBlock, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_READ,
        IRP_MJ_WRITE,
    },
    object::{AccessMask, ObjectAttributes, GENERIC_READ, GENERIC_WRITE},
    status::{
        NtStatus, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
        STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
    },
    string::UnicodeString,
};

use crate::nt::{
    io::{io_get_next_irp_stack_location, IoAllocateIrp, IoCallDriver},
    mm::{ExAllocatePoolWithTag, ExFreePoolWithTag, NonPagedPool},
    ob::{
        ob_close_handle, ob_create_handle, ob_insert_file, ob_reference_object_by_handle,
        ob_reference_object_by_name, OB_TYPE_FILE,
    },
};

pub const FILE_TAG: u32 = 0x656C6946; // 'File'

#[no_mangle]
pub unsafe extern "win64" fn ZwCreateFile(
    file_handle: *mut usize,
    desired_access: AccessMask,
    object_attributes: *mut ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    _allocation_size: *mut i64,
    _file_attributes: u32,
    _share_access: u32,
    _create_disposition: u32,
    _create_options: u32,
    _ea_buffer: *mut core::ffi::c_void,
    _ea_length: u32,
) -> NtStatus {
    if file_handle.is_null() || object_attributes.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let obj_name = (*object_attributes).object_name;
    if obj_name.is_null() || (*obj_name).buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let u16_slice =
        core::slice::from_raw_parts((*obj_name).buffer, ((*obj_name).length / 2) as usize);
    let mut name_buf = [0u8; 64];
    let mut idx = 0;
    for &ch in u16_slice {
        if idx < 63 {
            name_buf[idx] = ch as u8;
            idx += 1;
        }
    }
    let path = core::str::from_utf8_unchecked(&name_buf[..idx]);
    kprintln!("[ZW] ZwCreateFile: opening \"{}\" (Access: 0x{:08X})", path, desired_access);

    // 1. Resolve target object from Object Manager namespace
    let dev_header = match ob_reference_object_by_name(path) {
        Ok(h) => h,
        Err(status) => {
            kprintln!("[ZW] ZwCreateFile: Object \"{}\" not found (Status: 0x{:08X})", path, status);
            return status;
        }
    };

    let dev_obj = (*dev_header).body as *mut DeviceObject;
    if dev_obj.is_null() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // 2. Allocate FileObject from NonPagedPool
    let file_obj_size = core::mem::size_of::<FileObject>();
    let file_obj = ExAllocatePoolWithTag(NonPagedPool, file_obj_size, FILE_TAG) as *mut FileObject;
    if file_obj.is_null() {
        return STATUS_NO_MEMORY;
    }
    core::ptr::write_bytes(file_obj as *mut u8, 0, file_obj_size);

    (*file_obj).r#type = 5; // IO_TYPE_FILE
    (*file_obj).size = file_obj_size as u16;
    (*file_obj).device_object = dev_obj;
    (*file_obj).read_access = if (desired_access & GENERIC_READ) != 0 { 1 } else { 0 };
    (*file_obj).write_access = if (desired_access & GENERIC_WRITE) != 0 { 1 } else { 0 };

    // 3. Register FileObject in Object Manager and assign handle
    let file_header = ob_insert_file(file_obj as *mut u8, path);
    let handle = ob_create_handle(file_header, desired_access);
    *file_handle = handle;

    // 4. Build and dispatch IRP_MJ_CREATE to the device
    let stack_size = (*dev_obj).stack_size.max(1);
    let irp = IoAllocateIrp(stack_size, 0);
    if !irp.is_null() {
        let stack = io_get_next_irp_stack_location(irp);
        (*stack).major_function = IRP_MJ_CREATE;
        (*stack).file_object = file_obj as *mut core::ffi::c_void;
        (*stack).device_object = dev_obj;

        let status = IoCallDriver(dev_obj, irp);
        (*io_status_block).status = status;
        (*io_status_block).information = 1; // FILE_OPENED
        kprintln!("[ZW] ZwCreateFile dispatched IRP_MJ_CREATE: HANDLE 0x{:X}, Status: 0x{:08X}", handle, status);
        return status;
    }

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 1;
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwWriteFile(
    file_handle: usize,
    _event: usize,
    _apc_routine: *mut core::ffi::c_void,
    _apc_context: *mut core::ffi::c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *const core::ffi::c_void,
    length: u32,
    _byte_offset: *mut i64,
    _key: *mut u32,
) -> NtStatus {
    if io_status_block.is_null() || (buffer.is_null() && length > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    let header = match ob_reference_object_by_handle(file_handle) {
        Ok(h) => h,
        Err(status) => return status,
    };

    let file_obj = (*header).body as *mut FileObject;
    if file_obj.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let dev_obj = (*file_obj).device_object;
    if dev_obj.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    let stack_size = (*dev_obj).stack_size.max(1);
    let irp = IoAllocateIrp(stack_size, 0);
    if irp.is_null() {
        return STATUS_NO_MEMORY;
    }

    (*irp).user_buffer = buffer as *mut core::ffi::c_void;
    let stack = io_get_next_irp_stack_location(irp);
    (*stack).major_function = IRP_MJ_WRITE;
    (*stack).device_object = dev_obj;
    (*stack).file_object = file_obj as *mut core::ffi::c_void;
    (*stack).parameters[0] = length as usize; // Length

    kprintln!(
        "[ZW] ZwWriteFile: HANDLE 0x{:X} -> Device 0x{:p} ({} bytes payload)",
        file_handle,
        dev_obj,
        length
    );
    let status = IoCallDriver(dev_obj, irp);
    (*io_status_block).status = status;
    (*io_status_block).information = length as usize;
    status
}

#[no_mangle]
pub unsafe extern "win64" fn ZwReadFile(
    file_handle: usize,
    _event: usize,
    _apc_routine: *mut core::ffi::c_void,
    _apc_context: *mut core::ffi::c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *mut core::ffi::c_void,
    length: u32,
    _byte_offset: *mut i64,
    _key: *mut u32,
) -> NtStatus {
    if io_status_block.is_null() || (buffer.is_null() && length > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    let header = match ob_reference_object_by_handle(file_handle) {
        Ok(h) => h,
        Err(status) => return status,
    };

    let file_obj = (*header).body as *mut FileObject;
    if file_obj.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let dev_obj = (*file_obj).device_object;
    if dev_obj.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    let stack_size = (*dev_obj).stack_size.max(1);
    let irp = IoAllocateIrp(stack_size, 0);
    if irp.is_null() {
        return STATUS_NO_MEMORY;
    }

    (*irp).user_buffer = buffer;
    let stack = io_get_next_irp_stack_location(irp);
    (*stack).major_function = IRP_MJ_READ;
    (*stack).device_object = dev_obj;
    (*stack).file_object = file_obj as *mut core::ffi::c_void;
    (*stack).parameters[0] = length as usize;

    let status = IoCallDriver(dev_obj, irp);
    (*io_status_block).status = status;
    status
}

#[no_mangle]
pub unsafe extern "win64" fn ZwClose(handle: usize) -> NtStatus {
    kprintln!("[ZW] ZwClose: closing HANDLE 0x{:X}", handle);
    let header = match ob_reference_object_by_handle(handle) {
        Ok(h) => h,
        Err(status) => return status,
    };

    if (*header).object_type == &raw mut OB_TYPE_FILE {
        let file_obj = (*header).body as *mut FileObject;
        if !file_obj.is_null() {
            let dev_obj = (*file_obj).device_object;
            if !dev_obj.is_null() {
                let stack_size = (*dev_obj).stack_size.max(1);
                let irp = IoAllocateIrp(stack_size, 0);
                if !irp.is_null() {
                    let stack = io_get_next_irp_stack_location(irp);
                    (*stack).major_function = IRP_MJ_CLOSE;
                    (*stack).device_object = dev_obj;
                    (*stack).file_object = file_obj as *mut core::ffi::c_void;
                    IoCallDriver(dev_obj, irp);
                }
            }
            ExFreePoolWithTag(file_obj as *mut core::ffi::c_void, FILE_TAG);
        }
    }

    ob_close_handle(handle)
}

#[no_mangle]
pub unsafe extern "win64" fn ZwLoadDriver(driver_service_name: *mut UnicodeString) -> NtStatus {
    kprintln!("[ZW] ZwLoadDriver: request to dynamically load driver at 0x{:p}", driver_service_name);
    STATUS_SUCCESS
}
