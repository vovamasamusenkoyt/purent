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

use purent_ntdef::dialog::DialogText;

#[link(name = "user32", kind = "raw-dylib")]
extern "system" {
    fn PureNtShowDialog(text: *const DialogText) -> i32;
}

static ABOUT: DialogText = DialogText::new(
    "About PureNT",
    [
        "PureNT",
        "NT compatibility: 6.1 (Build 7601)",
        "Opened by winver.exe",
    ],
    "OK",
);

#[no_mangle]
pub unsafe extern "win64" fn ShellAboutW(
    _parent: usize,
    application: *const u16,
    _other: *const u16,
    _icon: usize,
) -> i32 {
    if application.is_null() || *application == 0 {
        return 0;
    }
    PureNtShowDialog(&ABOUT)
}
