//! Windows NT Virtual Memory Definitions
//! Reverse-engineered from ntoskrnl.exe and ntdll.dll

// Allocation types
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_DECOMMIT: u32 = 0x00004000;
pub const MEM_RELEASE: u32 = 0x00008000;
pub const MEM_FREE: u32 = 0x00010000;
pub const MEM_PRIVATE: u32 = 0x00020000;
pub const MEM_MAPPED: u32 = 0x00040000;
pub const MEM_RESET: u32 = 0x00080000;
pub const MEM_TOP_DOWN: u32 = 0x00100000;
pub const MEM_IMAGE: u32 = 0x01000000;

// Page protection flags
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

// Memory information classes
pub const MEMORY_BASIC_INFORMATION: u32 = 0;
pub const MEMORY_WORKING_SET_INFORMATION: u32 = 1;
pub const MEMORY_MAPPED_FILENAME_INFORMATION: u32 = 2;
pub const MEMORY_REGION_INFORMATION: u32 = 3;
pub const MEMORY_WORKING_SET_EX_INFORMATION: u32 = 4;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MemoryBasicInformation {
    pub base_address: *mut core::ffi::c_void,
    pub allocation_base: *mut core::ffi::c_void,
    pub allocation_protect: u32,
    pub __alignment1: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub r#type: u32,
    pub __alignment2: u32,
}
