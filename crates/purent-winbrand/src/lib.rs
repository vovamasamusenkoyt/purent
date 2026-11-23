#![no_std]
#![allow(non_snake_case)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "system" fn DllMain(_: usize, _: u32, _: usize) -> i32 {
    1
}

#[path = "../../purent-ntdef/src/freestanding.rs"]
mod freestanding;

mod winbrand;
