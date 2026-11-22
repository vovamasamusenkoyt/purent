//! x86_64 CPU instructions and port I/O

use core::arch::asm;

pub const IA32_GS_BASE: u32 = 0xC0000101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
pub const IA32_EFER: u32 = 0xC0000080;
pub const IA32_STAR: u32 = 0xC0000081;
pub const IA32_LSTAR: u32 = 0xC0000082;
pub const IA32_FMASK: u32 = 0xC0000084;

#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    asm!("in ax, dx", in("dx") port, out("ax") val, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high, options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nostack, preserves_flags));
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub unsafe fn read_cr2() -> u64 {
    let val: u64;
    asm!("mov {}, cr2", out(reg) val, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn read_cr3() -> u64 {
    let val: u64;
    asm!("mov {}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn write_cr3(val: u64) {
    asm!("mov cr3, {}", in(reg) val, options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn invlpg(va: u64) {
    asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn cli() {
    asm!("cli", options(nomem, nostack));
}

#[inline(always)]
pub unsafe fn sti() {
    asm!("sti", options(nomem, nostack));
}

#[inline(always)]
pub unsafe fn halt() {
    asm!("hlt", options(nomem, nostack));
}

#[inline(always)]
pub unsafe fn swapgs() {
    asm!("swapgs", options(nomem, nostack));
}

#[inline(always)]
pub unsafe fn read_gs_u64(offset: u32) -> u64 {
    let val: u64;
    match offset {
        0x10 => asm!("mov {}, gs:[0x10]", out(reg) val, options(nomem, nostack, preserves_flags)),
        0x20 => asm!("mov {}, gs:[0x20]", out(reg) val, options(nomem, nostack, preserves_flags)),
        0x188 => asm!("mov {}, gs:[0x188]", out(reg) val, options(nomem, nostack, preserves_flags)),
        0x1A8 => asm!("mov {}, gs:[0x1A8]", out(reg) val, options(nomem, nostack, preserves_flags)),
        _ => {
            // General GS read with variable offset
            asm!("mov rax, gs:[{offset:e}]", offset = in(reg) offset, lateout("rax") val, options(nomem, nostack, preserves_flags));
        }
    }
    val
}

#[inline(always)]
pub unsafe fn write_gs_u64(offset: u32, val: u64) {
    match offset {
        0x10 => asm!("mov gs:[0x10], {}", in(reg) val, options(nomem, nostack, preserves_flags)),
        0x188 => asm!("mov gs:[0x188], {}", in(reg) val, options(nomem, nostack, preserves_flags)),
        _ => {
            asm!("mov gs:[{offset:e}], {val}", offset = in(reg) offset, val = in(reg) val, options(nomem, nostack, preserves_flags));
        }
    }
}

#[inline(always)]
pub unsafe fn read_current_thread<T>() -> *mut T {
    read_gs_u64(0x188) as *mut T
}

#[inline(always)]
pub fn hlt_loop() -> ! {
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}
