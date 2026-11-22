//! Object attributes and access masks

use crate::string::UnicodeString;

pub type AccessMask = u32;

pub const GENERIC_READ: AccessMask = 0x80000000;
pub const GENERIC_WRITE: AccessMask = 0x40000000;
pub const GENERIC_EXECUTE: AccessMask = 0x20000000;
pub const GENERIC_ALL: AccessMask = 0x10000000;

pub const OBJ_INHERIT: u32 = 0x00000002;
pub const OBJ_PERMANENT: u32 = 0x00000010;
pub const OBJ_EXCLUSIVE: u32 = 0x00000020;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const OBJ_OPENIF: u32 = 0x00000080;
pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: *mut core::ffi::c_void,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut core::ffi::c_void,
    pub security_quality_of_service: *mut core::ffi::c_void,
}

unsafe impl Send for ObjectAttributes {}
unsafe impl Sync for ObjectAttributes {}

impl ObjectAttributes {
    pub const fn empty() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes: 0,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        }
    }
}
