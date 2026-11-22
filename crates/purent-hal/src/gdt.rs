//! Global Descriptor Table (GDT) and Task State Segment (TSS) for x86_64

use core::arch::asm;

pub const KERNEL_CS: u16 = 0x10;
pub const KERNEL_DS: u16 = 0x18;
pub const USER_CS32: u16 = 0x20 | 3;
pub const USER_DS: u16 = 0x28 | 3;
pub const USER_CS: u16 = 0x30 | 3;
pub const TSS_SEL: u16 = 0x40;

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct TaskStateSegment {
    reserved_1: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    reserved_2: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    reserved_3: u64,
    reserved_4: u16,
    pub iomap_base: u16,
}

#[repr(C, align(16))]
pub struct Gdt {
    entries: [u64; 10],
}

#[repr(C, packed)]
struct GdtDescriptor {
    size: u16,
    offset: u64,
}

static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved_1: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved_2: 0,
    ist1: 0,
    ist2: 0,
    ist3: 0,
    ist4: 0,
    ist5: 0,
    ist6: 0,
    ist7: 0,
    reserved_3: 0,
    reserved_4: 0,
    iomap_base: core::mem::size_of::<TaskStateSegment>() as u16,
};

static mut GDT: Gdt = Gdt {
    entries: [
        0,                  // 0x00: Null
        0,                  // 0x08: Reserved
        0x00AF9A000000FFFF, // 0x10: Kernel CS (64-bit, DPL 0, RX)
        0x00CF92000000FFFF, // 0x18: Kernel DS (DPL 0, RW)
        0x00CFFA000000FFFF, // 0x20: User CS (32-bit compat, DPL 3, RX)
        0x00CFF2000000FFFF, // 0x28: User DS (64-bit, DPL 3, RW)
        0x00AFFA000000FFFF, // 0x30: User CS (64-bit, DPL 3, RX)
        0,                  // 0x38: Reserved / TEB
        0,                  // 0x40: TSS low (set at runtime)
        0,                  // 0x48: TSS high
    ],
};

pub unsafe fn init() {
    let tss_ptr = &raw const TSS as usize as u64;
    let tss_size = core::mem::size_of::<TaskStateSegment>() as u64 - 1;

    // TSS descriptor low
    let mut tss_low = 0x0000890000000000u64;
    tss_low |= tss_size & 0xFFFF;
    tss_low |= (tss_ptr & 0x00FFFFFF) << 16;
    tss_low |= (tss_ptr & 0xFF000000) << 32;

    // TSS descriptor high
    let tss_high = tss_ptr >> 32;

    GDT.entries[8] = tss_low;
    GDT.entries[9] = tss_high;

    let gdtr = GdtDescriptor {
        size: (core::mem::size_of::<Gdt>() - 1) as u16,
        offset: &raw const GDT as u64,
    };

    asm!(
        "lgdt [{0}]",
        "push {1}",
        "lea rax, [2f + rip]",
        "push rax",
        "retfq",
        "2:",
        "mov ax, {2:x}",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov ss, ax",
        "mov ax, {3:x}",
        "ltr ax",
        in(reg) &gdtr,
        const KERNEL_CS,
        in(reg) KERNEL_DS,
        in(reg) TSS_SEL,
        out("rax") _,
        options(preserves_flags)
    );
}

pub unsafe extern "win64" fn set_rsp0(rsp: u64) {
    TSS.rsp0 = rsp;
}
