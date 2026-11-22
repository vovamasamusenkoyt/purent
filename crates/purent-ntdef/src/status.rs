//! NTSTATUS codes and helper macros

pub type NtStatus = i32;

pub const STATUS_SUCCESS: NtStatus = 0x00000000;
pub const STATUS_WAIT_0: NtStatus = 0x00000000;
pub const STATUS_PENDING: NtStatus = 0x00000103;

pub const STATUS_UNSUCCESSFUL: NtStatus = -1073741823; // 0xC0000001
pub const STATUS_NOT_IMPLEMENTED: NtStatus = -1073741822; // 0xC0000002
pub const STATUS_INVALID_INFO_CLASS: NtStatus = -1073741821; // 0xC0000003
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = -1073741820; // 0xC0000004
pub const STATUS_ACCESS_VIOLATION: NtStatus = -1073741819; // 0xC0000005
pub const STATUS_INVALID_HANDLE: NtStatus = -1073741816; // 0xC0000008
pub const STATUS_INVALID_PARAMETER: NtStatus = -1073741811; // 0xC000000D
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC0000022u32 as i32;
pub const STATUS_NO_MEMORY: NtStatus = -1073741801; // 0xC0000017
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = -1073741800; // 0xC0000018
pub const STATUS_NOT_MAPPED_VIEW: NtStatus = -1073741799; // 0xC0000019
pub const STATUS_UNABLE_TO_FREE_VM: NtStatus = -1073741798; // 0xC000001A
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = -1073741789; // 0xC0000023
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = -1073741772; // 0xC0000034
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = -1073741771; // 0xC0000035
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = -1073741766; // 0xC000003A
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = -1073741808; // 0xC0000010
pub const STATUS_INVALID_ADDRESS: NtStatus = -1073741499; // 0xC0000141
pub const STATUS_IO_DEVICE_ERROR: NtStatus = -1073741637; // 0xC0000185
pub const STATUS_NOT_SUPPORTED: NtStatus = -1073741595; // 0xC00000BB

#[inline(always)]
pub const fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

#[inline(always)]
pub const fn nt_error(status: NtStatus) -> bool {
    status < 0
}
