//! NT Run-Time Library (Rtl) String Functions

use purent_ntdef::string::UnicodeString;

#[no_mangle]
pub unsafe extern "win64" fn RtlInitUnicodeString(
    destination_string: *mut UnicodeString,
    source_string: *const u16,
) {
    if destination_string.is_null() {
        return;
    }
    if source_string.is_null() {
        *destination_string = UnicodeString::empty();
        return;
    }
    let mut len = 0usize;
    while *source_string.add(len) != 0 {
        len += 1;
    }
    let bytes_len = (len * 2) as u16;
    (*destination_string).length = bytes_len;
    (*destination_string).maximum_length = bytes_len + 2;
    (*destination_string).buffer = source_string as *mut u16;
}
