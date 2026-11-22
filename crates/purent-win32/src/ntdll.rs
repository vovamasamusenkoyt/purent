//! PureNT Clean-Room NTDLL Emulation Subsystem (ntdll.dll)
//! Reverse-engineered functions required by cmd.exe

use purent_ntdef::status::{NtStatus, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};

#[no_mangle]
pub unsafe extern "win64" fn RtlCaptureContext(_context: *mut core::ffi::c_void) {}

#[no_mangle]
pub unsafe extern "win64" fn RtlLookupFunctionEntry(
    _control_pc: u64,
    image_base: *mut u64,
    _history_table: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if !image_base.is_null() {
        *image_base = 0x000000004ad00000;
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "win64" fn RtlVirtualUnwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _handler_data: *mut *mut core::ffi::c_void,
    establisher_frame: *mut u64,
    _context_pointers: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if !establisher_frame.is_null() {
        *establisher_frame = 0;
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "win64" fn RtlFreeHeap(
    _heap: usize,
    _flags: u32,
    _base_address: *mut core::ffi::c_void,
) -> u8 {
    1
}

#[no_mangle]
pub unsafe extern "win64" fn NtFsControlFile(
    _file_handle: usize,
    _event: usize,
    _apc_routine: *mut core::ffi::c_void,
    _apc_context: *mut core::ffi::c_void,
    io_status_block: *mut purent_ntdef::io::IoStatusBlock,
    _fs_control_code: u32,
    _input_buffer: *mut core::ffi::c_void,
    _input_buffer_length: u32,
    _output_buffer: *mut core::ffi::c_void,
    _output_buffer_length: u32,
) -> NtStatus {
    if !io_status_block.is_null() {
        (*io_status_block).status = STATUS_SUCCESS;
    }
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn NtOpenThreadToken(
    _thread: usize,
    _access: u32,
    _open_as_self: u8,
    token_handle: *mut usize,
) -> NtStatus {
    if !token_handle.is_null() { *token_handle = 0x20; }
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn NtOpenProcessToken(
    _process: usize,
    _access: u32,
    token_handle: *mut usize,
) -> NtStatus {
    if !token_handle.is_null() { *token_handle = 0x20; }
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn NtQueryInformationToken(
    _token: usize,
    _token_info_class: u32,
    _token_info: *mut core::ffi::c_void,
    _token_info_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    if !return_length.is_null() { *return_length = 0; }
    STATUS_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "win64" fn RtlDosPathNameToNtPathName_U(
    _dos_path_name: *const u16,
    nt_path_name: *mut purent_ntdef::string::UnicodeString,
    _nt_file_name_part: *mut *mut u16,
    _relative_name: *mut core::ffi::c_void,
) -> u8 {
    if !nt_path_name.is_null() {
        *nt_path_name = purent_ntdef::string::UnicodeString::empty();
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn RtlFindLeastSignificantBit(set: u64) -> u8 {
    if set == 0 {
        255
    } else {
        set.trailing_zeros() as u8
    }
}

#[no_mangle]
pub unsafe extern "win64" fn NtSetInformationProcess(
    _process: usize,
    _info_class: u32,
    _info: *mut core::ffi::c_void,
    _info_length: u32,
) -> NtStatus {
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn NtQueryInformationProcess(
    _process: usize,
    _info_class: u32,
    _info: *mut core::ffi::c_void,
    _info_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    if !return_length.is_null() { *return_length = 0; }
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn RtlNtStatusToDosError(status: NtStatus) -> u32 {
    if status == 0 {
        0
    } else {
        1 // ERROR_INVALID_FUNCTION
    }
}
