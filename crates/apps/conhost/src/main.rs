//! User-mode console host. Turns keyboard input into edited console lines.

#![no_std]
#![no_main]

#[path = "../../../purent-ntdef/src/freestanding.rs"]
mod freestanding;

use purent_ntdef::syscall::{
    nt_syscall0, nt_syscall1, nt_syscall2, nt_syscall7, CONSOLE_LINE_CAPACITY,
    CONSOLE_OUTPUT_LENGTH_SHIFT, SYSCALL_PURENT_CONSOLE_EVENT, SYSCALL_PURENT_CONSOLE_OUTPUT,
    SYSCALL_PURENT_CONSOLE_SUBMIT,
};
use purent_ntdef::IoStatusBlock;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn echo(bytes: &[u8]) {
    let mut status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    nt_syscall7(
        0x05, // NtWriteFile
        4,
        0,
        0,
        0,
        (&mut status as *mut IoStatusBlock) as u64,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
    );
}

unsafe fn render_output(mut packet: u32) {
    let mut output = [0u8; 126];
    let mut used = 0;
    loop {
        let count = (packet >> CONSOLE_OUTPUT_LENGTH_SHIFT) as usize;
        if !(1..=3).contains(&count) {
            break;
        }
        for index in 0..count {
            output[used] = (packet >> (index * 8)) as u8;
            used += 1;
        }
        if output.len() - used < 3 {
            echo(&output[..used]);
            used = 0;
        }
        packet = nt_syscall0(SYSCALL_PURENT_CONSOLE_OUTPUT) as u32;
    }
    if used != 0 {
        echo(&output[..used]);
    }
}

#[no_mangle]
pub unsafe extern "C" fn main() -> ! {
    let mut line = [0u8; CONSOLE_LINE_CAPACITY];
    let mut length = 0;
    loop {
        let event = nt_syscall0(SYSCALL_PURENT_CONSOLE_EVENT);
        if event < 0 {
            exit(event);
        }
        let event = event as u32;
        if event >> CONSOLE_OUTPUT_LENGTH_SHIFT != 0 {
            render_output(event);
            continue;
        }
        match event {
            8 if length > 0 => {
                length -= 1;
                echo(b"\x08");
            }
            13 => {
                echo(b"\r\n");
                line[length..length + 2].copy_from_slice(b"\r\n");
                for &byte in &line[..length + 2] {
                    nt_syscall1(SYSCALL_PURENT_CONSOLE_SUBMIT, byte.into());
                }
                length = 0;
            }
            32..=126 if length < line.len() - 2 => {
                line[length] = event as u8;
                echo(&line[length..length + 1]);
                length += 1;
            }
            _ => {}
        }
    }
}

unsafe fn exit(status: i32) -> ! {
    nt_syscall2(0x29, u64::MAX, status as u64); // NtTerminateProcess
    loop {
        core::hint::spin_loop();
    }
}
