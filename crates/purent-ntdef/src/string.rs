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

/// Compare null-terminated UTF-16 strings using ASCII case folding.
pub unsafe fn compare_ascii_wide_insensitive(s1: *const u16, s2: *const u16) -> i32 {
    let mut i = 0;
    loop {
        let mut c1 = *s1.add(i);
        let mut c2 = *s2.add(i);
        if c1 >= 'A' as u16 && c1 <= 'Z' as u16 { c1 += 32; }
        if c2 >= 'A' as u16 && c2 <= 'Z' as u16 { c2 += 32; }
        if c1 != c2 || c1 == 0 {
            return (c1 as i32) - (c2 as i32);
        }
        i += 1;
    }
}
