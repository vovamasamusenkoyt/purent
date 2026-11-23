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
            for layer in job.layers[..job.layer_count].iter().rev() {
                let rect = layer.bounds;
                if y < rect.top || y >= rect.bottom || x >= rect.right {
                    continue;
                }
                if x < rect.left {
                    right = right.min(rect.left);
                } else {
                    right = right.min(rect.right);
                    source = Some(layer);
                    break;
                }
            }
            if let Some(layer) = source {
                let opaque = layer.opaque;
                let content_row = y >= opaque.top && y < opaque.bottom;
                let glass = layer.glass && (!content_row || x < opaque.left || x >= opaque.right);
                let source_row = (y as i32 - layer.origin_y) as usize * layer.stride;
                let source_left = (x as i32 - layer.origin_x) as usize;
                let source = (surface_address(layer.slot) as *const u32)
                    .add(source_row + source_left);
                if layer.glass && content_row {
                    if x < opaque.left {
                        right = right.min(opaque.left);
                    } else if x < opaque.right {
                        right = right.min(opaque.right);
                    }
                }

                if glass {
                    for (offset, x) in (x..right).enumerate() {
                        let pixel = *source.add(offset);
                        *output.add(row + x) = if pixel >> 24 == 255 {
                            pixel
                        } else {
                            blend_over(pixel, glass_pixel(x, y, job.width, job.height))
                        };
                    }
                } else {
                    core::arch::asm!(
                        "rep movsd",
                        inout("rsi") source => _,
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
