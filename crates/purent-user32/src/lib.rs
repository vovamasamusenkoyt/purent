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

use purent_pe::{PeView, IMAGE_DIRECTORY_ENTRY_RESOURCE};

static WINVER_MUI: &[u8] = include_bytes!("../../../target/esp/winver.exe.mui");

fn word(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn dword(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn resource_entry(data: &[u8], table: usize, id: u32) -> Option<u32> {
    let named = word(data, table + 12)? as usize;
    let ids = word(data, table + 14)? as usize;
    for index in named..named + ids {
        let entry = table + 16 + index * 8;
        if dword(data, entry)? == id {
            return dword(data, entry + 4);
        }
    }
    None
}

fn version_string(id: u32) -> Option<&'static [u8]> {
    let pe = PeView::parse(WINVER_MUI).ok()?;
    let directory = pe.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    let base = pe.rva_to_offset(directory.virtual_address)?;
    let resources = WINVER_MUI.get(base..base + directory.size as usize)?;
    let by_id = resource_entry(resources, 0, 6)? & 0x7FFF_FFFF;
    let by_lang = resource_entry(resources, by_id as usize, id / 16 + 1)? & 0x7FFF_FFFF;
    let entry = resource_entry(resources, by_lang as usize, 1033)? as usize;
    let offset = pe.rva_to_offset(dword(resources, entry)?)?;
    let mut strings = WINVER_MUI.get(offset..offset + dword(resources, entry + 4)? as usize)?;
    for index in 0..16 {
        let len = word(strings, 0)? as usize * 2;
        let text = strings.get(2..2 + len)?;
        if index == id % 16 {
            return Some(text);
        }
        strings = strings.get(2 + len..)?;
    }
    None
}

#[no_mangle]
pub unsafe extern "win64" fn LoadStringW(
    module: usize,
    id: u32,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if module != 0x1_0000_0000 || buffer.is_null() || size <= 0 {
        return 0;
    }
    let Some(text) = version_string(id) else {
        *buffer = 0;
        return 0;
    };
    let count = (text.len() / 2).min(size as usize - 1);
    for index in 0..count {
        *buffer.add(index) = u16::from_le_bytes([text[index * 2], text[index * 2 + 1]]);
    }
    *buffer.add(count) = 0;
    count as i32
}

/// Transitional entry point for an informational modal dialog.
#[no_mangle]
pub unsafe extern "system" fn PureNtShowDialog(
    text: *const purent_ntdef::dialog::DialogText,
) -> i32 {
    use purent_ntdef::syscall::{nt_syscall1, SYSCALL_PURENT_SHOW_DIALOG};
    (nt_syscall1(SYSCALL_PURENT_SHOW_DIALOG, text as u64) == 0) as i32
}

mod windows;
