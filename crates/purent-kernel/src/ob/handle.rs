//! NT Object Manager Handle Management and Resolution

use purent_hal::kprintln;
use purent_ntdef::{
    object::AccessMask,
    status::{NtStatus, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS},
};

use super::namespace::{
    create_header, ObjectHeader, OB_NAMESPACE, OB_TYPE_DEVICE, OB_TYPE_FILE,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HandleEntry {
    pub object: *mut ObjectHeader,
    pub granted_access: AccessMask,
}

pub struct HandleTable {
    pub next_handle: usize,
    pub entries: [HandleEntry; 128],
}

unsafe impl Send for HandleTable {}

pub static SYSTEM_HANDLE_TABLE: purent_hal::SpinLock<HandleTable> = purent_hal::SpinLock::new(HandleTable {
    next_handle: 4,
    entries: [HandleEntry {
        object: core::ptr::null_mut(),
        granted_access: 0,
    }; 128],
});

pub unsafe fn ob_insert_device(device_ptr: *mut u8, name: &str) -> NtStatus {
    let mut ns = OB_NAMESPACE.lock();
    let header = create_header(device_ptr, name, &raw mut OB_TYPE_DEVICE);
    (*header).parent_directory = &raw mut ns.device_dir;
    let status = ns.device_dir.insert(header);
    if status == STATUS_SUCCESS {
        kprintln!("[OB] Registered object in namespace: \\Device\\{}", name);
    }
    status
}

pub unsafe fn ob_insert_filesystem(device_ptr: *mut u8, name: &str) -> NtStatus {
    let mut ns = OB_NAMESPACE.lock();
    let header = create_header(device_ptr, name, &raw mut OB_TYPE_DEVICE);
    (*header).parent_directory = &raw mut ns.file_system_dir;
    let status = ns.file_system_dir.insert(header);
    if status == STATUS_SUCCESS {
        kprintln!("[OB] Registered object in namespace: \\FileSystem\\{}", name);
    }
    status
}

pub unsafe fn ob_insert_file(file_ptr: *mut u8, name: &str) -> *mut ObjectHeader {
    let header = create_header(file_ptr, name, &raw mut OB_TYPE_FILE);
    header
}

pub unsafe fn ob_close_handle(handle: usize) -> NtStatus {
    let handle_idx = handle / 4;
    let mut tbl = SYSTEM_HANDLE_TABLE.lock();
    if handle_idx == 0 || handle_idx >= tbl.entries.len() {
        return purent_ntdef::status::STATUS_INVALID_HANDLE;
    }
    let entry = &mut tbl.entries[handle_idx];
    if entry.object.is_null() {
        return purent_ntdef::status::STATUS_INVALID_HANDLE;
    }
    let header = entry.object;
    if (*header).handle_count > 0 {
        (*header).handle_count -= 1;
    }
    if (*header).pointer_count > 0 {
        (*header).pointer_count -= 1;
    }
    entry.object = core::ptr::null_mut();
    entry.granted_access = 0;
    STATUS_SUCCESS
}

pub unsafe fn ob_create_handle(object_header: *mut ObjectHeader, access: AccessMask) -> usize {
    let mut tbl = SYSTEM_HANDLE_TABLE.lock();
    let handle_idx = tbl.next_handle / 4;
    tbl.next_handle += 4;

    tbl.entries[handle_idx].object = object_header;
    tbl.entries[handle_idx].granted_access = access;
    (*object_header).handle_count += 1;

    let handle_val = handle_idx * 4;
    kprintln!("[OB] Created HANDLE 0x{:X} for object \"{}\"", handle_val, (*object_header).name_str());
    handle_val
}

pub unsafe fn ob_reference_object_by_name(path: &str) -> Result<*mut ObjectHeader, NtStatus> {
    let ns = OB_NAMESPACE.lock();
    if path.starts_with("\\Device\\") {
        let dev_name = &path["\\Device\\".len()..];
        if let Some(hdr) = ns.device_dir.lookup(dev_name) {
            (*hdr).pointer_count += 1;
            return Ok(hdr);
        }
    } else if path.starts_with("\\FileSystem\\") {
        let fs_name = &path["\\FileSystem\\".len()..];
        if let Some(hdr) = ns.file_system_dir.lookup(fs_name) {
            (*hdr).pointer_count += 1;
            return Ok(hdr);
        }
    }
    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

pub unsafe fn ob_reference_object_by_handle(handle: usize) -> Result<*mut ObjectHeader, NtStatus> {
    let handle_idx = handle / 4;
    let tbl = SYSTEM_HANDLE_TABLE.lock();
    if handle_idx == 0 || handle_idx >= tbl.entries.len() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let entry = &tbl.entries[handle_idx];
    if entry.object.is_null() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    (*entry.object).pointer_count += 1;
    Ok(entry.object)
}
