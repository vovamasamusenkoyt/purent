//! NT Object Manager (Ob) Namespace and Directories

use purent_hal::kprintln;
use purent_ntdef::status::{NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS};
use crate::mm::{ExAllocatePoolWithTag, NonPagedPool};

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

pub static mut OB_TYPE_SECTION: ObjectType = ObjectType {
    name: "Section",
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

pub struct ObjectNamespace {
    pub root_dir: ObjectDirectory,
    pub device_dir: ObjectDirectory,
    pub driver_dir: ObjectDirectory,
    pub dos_devices_dir: ObjectDirectory,
    pub file_system_dir: ObjectDirectory,
}

unsafe impl Send for ObjectNamespace {}

pub static OB_NAMESPACE: purent_hal::SpinLock<ObjectNamespace> = purent_hal::SpinLock::new(ObjectNamespace {
    root_dir: ObjectDirectory::new(),
    device_dir: ObjectDirectory::new(),
    driver_dir: ObjectDirectory::new(),
    dos_devices_dir: ObjectDirectory::new(),
    file_system_dir: ObjectDirectory::new(),
});

pub unsafe fn create_header(body: *mut u8, name: &str, obj_type: *mut ObjectType) -> *mut ObjectHeader {
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

pub unsafe fn insert_directory_entry(parent: *mut ObjectDirectory, child_dir: *mut ObjectDirectory, name: &'static str) {
    let header = create_header(child_dir as *mut u8, name, &raw mut OB_TYPE_DIRECTORY);
    (*header).parent_directory = parent;
    (*parent).insert(header);
}

pub unsafe fn ob_init() {
    let mut ns = OB_NAMESPACE.lock();

    // 1. Create root directory header
    let root_header = create_header(&raw mut ns.root_dir as *mut u8, "\\", &raw mut OB_TYPE_DIRECTORY);
    (*root_header).parent_directory = core::ptr::null_mut();

    // 2. Insert standard subdirectories into root
    insert_directory_entry(&raw mut ns.root_dir, &raw mut ns.device_dir, "Device");
    insert_directory_entry(&raw mut ns.root_dir, &raw mut ns.driver_dir, "Driver");
    insert_directory_entry(&raw mut ns.root_dir, &raw mut ns.dos_devices_dir, "DosDevices");
    insert_directory_entry(&raw mut ns.root_dir, &raw mut ns.file_system_dir, "FileSystem");

    kprintln!("[OB] Object Manager namespace initialized (Root: \\, \\Device, \\Driver, \\DosDevices, \\FileSystem)");
}
