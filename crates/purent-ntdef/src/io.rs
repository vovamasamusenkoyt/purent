//! I/O System, IRPs, Driver and Device objects

use crate::list::ListEntry;
use crate::string::UnicodeString;

pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_PNP: u8 = 0x1b;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1b;

pub const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;

pub const DO_BUFFERED_IO: u32 = 0x00000004;
pub const DO_DIRECT_IO: u32 = 0x00000010;
pub const DO_DEVICE_INITIALIZING: u32 = 0x00000080;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DeviceObject {
    pub r#type: i16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: *mut DriverObject,
    pub next_device: *mut DeviceObject,
    pub attached_device: *mut DeviceObject,
    pub current_irp: *mut Irp,
    pub timer: *mut core::ffi::c_void,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: *mut core::ffi::c_void,
    pub device_extension: *mut core::ffi::c_void,
    pub device_type: u32,
    pub stack_size: i8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DriverObject {
    pub r#type: i16,
    pub size: u16,
    pub device_object: *mut DeviceObject,
    pub flags: u32,
    pub driver_start: *mut core::ffi::c_void,
    pub driver_size: u32,
    pub driver_section: *mut core::ffi::c_void,
    pub driver_extension: *mut core::ffi::c_void,
    pub driver_name: UnicodeString,
    pub hardware_database: *mut UnicodeString,
    pub fast_io_dispatch: *mut core::ffi::c_void,
    pub driver_init: *mut core::ffi::c_void,
    pub driver_start_io: *mut core::ffi::c_void,
    pub driver_unload: *mut core::ffi::c_void,
    pub major_function: [*mut core::ffi::c_void; IRP_MJ_MAXIMUM_FUNCTION + 1],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoStatusBlock {
    pub status: i32,
    pub information: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: [usize; 4],
    pub device_object: *mut DeviceObject,
    pub file_object: *mut core::ffi::c_void,
    pub completion_routine: *mut core::ffi::c_void,
    pub context: *mut core::ffi::c_void,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Irp {
    pub r#type: i16,
    pub size: u16,
    pub mdl_address: *mut core::ffi::c_void,
    pub flags: u32,
    pub associated_irp_system_buffer: *mut core::ffi::c_void,
    pub thread_list_entry: ListEntry,
    pub io_status: IoStatusBlock,
    pub requestor_mode: i8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub cancel: u8,
    pub cancel_irql: u8,
    pub user_buffer: *mut core::ffi::c_void,
    pub tail: [u8; 128],
}
