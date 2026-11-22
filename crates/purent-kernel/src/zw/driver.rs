//! NT System Services for Driver Management (ZwLoadDriver)

use purent_hal::kprintln;
use purent_ntdef::{
    status::{NtStatus, STATUS_SUCCESS},
    string::UnicodeString,
};

#[no_mangle]
pub unsafe extern "win64" fn ZwLoadDriver(driver_service_name: *mut UnicodeString) -> NtStatus {
    kprintln!("[ZW] ZwLoadDriver: request to dynamically load driver at 0x{:p}", driver_service_name);
    STATUS_SUCCESS
}
