//! NT Object Manager (Ob) Subsystem

use purent_hal::kprintln;
use purent_ntdef::{
    object::AccessMask,
    status::{NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS},
};
use crate::nt::mm::{ExAllocatePoolWithTag, NonPagedPool};

pub const OB_TAG: u32 = 0x656A624F; // 'Obje'

#[repr(C)]
#[derive(Debug)]
pub struct ObjectType {
    pub name: &'static str,
    pub total_number_of_objects: u32,
    pub total_number_of_handles: u32,
}

pub static mut OB_TYPE_DIRECTORY: ObjectType = ObjectType {
    name: "Directory",
    total_number_of_objects: 0,
    total_number_of_handles: 0,
};

pub static mut OB_TYPE_DEVICE: ObjectType = ObjectType {
    name: "Device",
    total_number_of_objects: 0,
    total_number_of_handles: 0,
};

pub static mut OB_TYPE_DRIVER: ObjectType = ObjectType {
    name: "Driver",
    total_number_of_objects: 0,
    total_number_of_handles: 0,
};

pub static mut OB_TYPE_SYMLINK: ObjectType = ObjectType {
    name: "SymbolicLink",
    total_number_of_objects: 0,
    total_number_of_handles: 0,
};

pub static mut OB_TYPE_FILE: ObjectType = ObjectType {
    name: "File",
    total_number_of_objects: 0,
    total_number_of_handles: 0,
};

#[repr(C)]
pub struct ObjectHeader {
    pub pointer_count: i64,
    pub handle_count: i64,
    pub object_type: *mut ObjectType,
    pub body: *mut u8,
    pub name: [u8; 64],
    pub name_len: usize,
    pub parent_directory: *mut ObjectDirectory,
}

impl ObjectHeader {
    pub fn name_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.name[..self.name_len]) }
    }
}

pub const MAX_DIR_ENTRIES: usize = 32;

#[repr(C)]
pub struct ObjectDirectory {
    pub count: usize,
    pub entries: [*mut ObjectHeader; MAX_DIR_ENTRIES],
}

impl ObjectDirectory {
    pub const fn new() -> Self {
        Self {
            count: 0,
            entries: [core::ptr::null_mut(); MAX_DIR_ENTRIES],
        }
    }

    pub unsafe fn insert(&mut self, header: *mut ObjectHeader) -> NtStatus {
        if self.count >= MAX_DIR_ENTRIES {
            return -1073741801; // STATUS_NO_MEMORY
        }
        let name = (*header).name_str();
        for i in 0..self.count {
            if (*self.entries[i]).name_str() == name {
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
        self.entries[self.count] = header;
        self.count += 1;
        STATUS_SUCCESS
    }

    pub unsafe fn lookup(&self, name: &str) -> Option<*mut ObjectHeader> {
        for i in 0..self.count {
            if (*self.entries[i]).name_str() == name {
                return Some(self.entries[i]);
            }
        }
        None
    }
}

// Fixed root namespaces
static mut ROOT_DIR: ObjectDirectory = ObjectDirectory::new();
static mut DEVICE_DIR: ObjectDirectory = ObjectDirectory::new();
static mut DRIVER_DIR: ObjectDirectory = ObjectDirectory::new();
static mut DOS_DEVICES_DIR: ObjectDirectory = ObjectDirectory::new();
static mut FILE_SYSTEM_DIR: ObjectDirectory = ObjectDirectory::new();

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HandleEntry {
    pub object: *mut ObjectHeader,
    pub granted_access: AccessMask,
}

static mut SYSTEM_HANDLE_TABLE: [HandleEntry; 128] = [HandleEntry {
    object: core::ptr::null_mut(),
    granted_access: 0,
}; 128];
static mut NEXT_HANDLE: usize = 4; // NT Handles start at 4 (multiples of 4)

pub unsafe fn ob_init() {
    // 1. Create root directory header
    let root_header = create_header(&raw mut ROOT_DIR as *mut u8, "\\", &raw mut OB_TYPE_DIRECTORY);
    (*root_header).parent_directory = core::ptr::null_mut();

    // 2. Insert standard subdirectories into root
    insert_directory_entry(&raw mut ROOT_DIR, &raw mut DEVICE_DIR, "Device");
    insert_directory_entry(&raw mut ROOT_DIR, &raw mut DRIVER_DIR, "Driver");
    insert_directory_entry(&raw mut ROOT_DIR, &raw mut DOS_DEVICES_DIR, "DosDevices");
    insert_directory_entry(&raw mut ROOT_DIR, &raw mut FILE_SYSTEM_DIR, "FileSystem");

    kprintln!("[OB] Object Manager namespace initialized (Root: \\, \\Device, \\Driver, \\DosDevices, \\FileSystem)");
}

unsafe fn create_header(body: *mut u8, name: &str, obj_type: *mut ObjectType) -> *mut ObjectHeader {
    let header_size = core::mem::size_of::<ObjectHeader>();
    let ptr = ExAllocatePoolWithTag(NonPagedPool, header_size, OB_TAG) as *mut ObjectHeader;
    core::ptr::write_bytes(ptr as *mut u8, 0, header_size);

    (*ptr).pointer_count = 1;
    (*ptr).handle_count = 0;
    (*ptr).object_type = obj_type;
    (*ptr).body = body;

    let bytes = name.as_bytes();
    let copy_len = if bytes.len() > 63 { 63 } else { bytes.len() };
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), (*ptr).name.as_mut_ptr(), copy_len);
    (*ptr).name_len = copy_len;

    (*obj_type).total_number_of_objects += 1;
    ptr
}

unsafe fn insert_directory_entry(parent: *mut ObjectDirectory, child_dir: *mut ObjectDirectory, name: &'static str) {
    let header = create_header(child_dir as *mut u8, name, &raw mut OB_TYPE_DIRECTORY);
    (*header).parent_directory = parent;
    (*parent).insert(header);
}

pub unsafe fn ob_insert_device(device_ptr: *mut u8, name: &str) -> NtStatus {
    let header = create_header(device_ptr, name, &raw mut OB_TYPE_DEVICE);
    (*header).parent_directory = &raw mut DEVICE_DIR;
    let status = DEVICE_DIR.insert(header);
    if status == STATUS_SUCCESS {
        kprintln!("[OB] Registered object in namespace: \\Device\\{}", name);
    }
    status
}

pub unsafe fn ob_insert_filesystem(device_ptr: *mut u8, name: &str) -> NtStatus {
    let header = create_header(device_ptr, name, &raw mut OB_TYPE_DEVICE);
    (*header).parent_directory = &raw mut FILE_SYSTEM_DIR;
    let status = FILE_SYSTEM_DIR.insert(header);
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
    if handle_idx == 0 || handle_idx >= SYSTEM_HANDLE_TABLE.len() {
        return purent_ntdef::status::STATUS_INVALID_HANDLE;
    }
    let entry = &mut SYSTEM_HANDLE_TABLE[handle_idx];
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
    let handle_idx = NEXT_HANDLE / 4;
    NEXT_HANDLE += 4;

    SYSTEM_HANDLE_TABLE[handle_idx].object = object_header;
    SYSTEM_HANDLE_TABLE[handle_idx].granted_access = access;
    (*object_header).handle_count += 1;

    let handle_val = handle_idx * 4;
    kprintln!("[OB] Created HANDLE 0x{:X} for object \"{}\"", handle_val, (*object_header).name_str());
    handle_val
}

pub unsafe fn ob_reference_object_by_name(path: &str) -> Result<*mut ObjectHeader, NtStatus> {
    if path.starts_with("\\Device\\") {
        let dev_name = &path["\\Device\\".len()..];
        if let Some(hdr) = DEVICE_DIR.lookup(dev_name) {
            (*hdr).pointer_count += 1;
            return Ok(hdr);
        }
    } else if path.starts_with("\\FileSystem\\") {
        let fs_name = &path["\\FileSystem\\".len()..];
        if let Some(hdr) = FILE_SYSTEM_DIR.lookup(fs_name) {
            (*hdr).pointer_count += 1;
            return Ok(hdr);
        }
    }
    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

pub unsafe fn ob_reference_object_by_handle(handle: usize) -> Result<*mut ObjectHeader, NtStatus> {
    let handle_idx = handle / 4;
    if handle_idx == 0 || handle_idx >= SYSTEM_HANDLE_TABLE.len() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let entry = &SYSTEM_HANDLE_TABLE[handle_idx];
    if entry.object.is_null() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    (*entry.object).pointer_count += 1;
    Ok(entry.object)
}
