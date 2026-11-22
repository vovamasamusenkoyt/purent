//! NT String definitions (UNICODE_STRING, ANSI_STRING)

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

unsafe impl Send for UnicodeString {}
unsafe impl Sync for UnicodeString {}

impl UnicodeString {
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        }
    }

    pub const fn from_raw_parts(buffer: *mut u16, length: u16, maximum_length: u16) -> Self {
        Self {
            length,
            maximum_length,
            buffer,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AnsiString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u8,
}

unsafe impl Send for AnsiString {}
unsafe impl Sync for AnsiString {}
