//! User-mode desktop compositor for PureNT.

#![no_std]
#![no_main]

#[path = "../../../purent-ntdef/src/freestanding.rs"]
mod freestanding;

use purent_ntdef::composition::*;
use purent_ntdef::syscall::{
    nt_syscall0, SYSCALL_PURENT_COMPOSE_FINISH, SYSCALL_PURENT_COMPOSE_RECEIVE,
};

mod backdrop;

use backdrop::{glass_pixel, wallpaper_pixel};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn compose(job: &CompositionJob) {
    let output = OUTPUT_ADDRESS as *mut u32;
    for y in job.dirty.top..job.dirty.bottom {
        let row = y * job.width;
        let wallpaper_y = y * 400 / job.height;
        let mut x = job.dirty.left;
        while x < job.dirty.right {
            let mut right = job.dirty.right;
            let mut source = None;
            for (rect, address) in [(job.dialog, DIALOG_ADDRESS), (job.console, CONSOLE_ADDRESS)] {
                if y < rect.top || y >= rect.bottom || x >= rect.right {
                    continue;
                }
                if x < rect.left {
                    right = right.min(rect.left);
                } else {
                    right = right.min(rect.right);
                    source = Some(address as *const u32);
                    break;
                }
            }
            if let Some(source) = source {
                let opaque = job.console_opaque;
                let console = source == CONSOLE_ADDRESS as *const u32;
                let content_row = y >= opaque.top && y < opaque.bottom;
                let glass = console && (!content_row || x < opaque.left || x >= opaque.right);
                if console && content_row {
                    if x < opaque.left {
                        right = right.min(opaque.left);
                    } else if x < opaque.right {
                        right = right.min(opaque.right);
                    }
                }

                if glass {
                    for x in x..right {
                        let pixel = *source.add(row + x);
                        *output.add(row + x) = if pixel == GLASS_PIXEL {
                            glass_pixel(x, y, job.width, job.height)
                        } else {
                            pixel
                        };
                    }
                } else {
                    core::arch::asm!(
                        "rep movsd",
                        inout("rsi") source.add(row + x) => _,
                        inout("rdi") output.add(row + x) => _,
                        inout("rcx") right - x => _,
                        options(nostack, preserves_flags),
                    );
                }
            } else {
                for x in x..right {
                    *output.add(row + x) = wallpaper_pixel(x * 640 / job.width, wallpaper_y);
                }
            }
            x = right;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn main() -> ! {
    loop {
        if nt_syscall0(SYSCALL_PURENT_COMPOSE_RECEIVE) != 0 {
            loop {
                core::hint::spin_loop();
            }
        }
        let job = core::ptr::read_volatile(JOB_ADDRESS as *const CompositionJob);
        compose(&job);
        nt_syscall0(SYSCALL_PURENT_COMPOSE_FINISH);
    }
}
