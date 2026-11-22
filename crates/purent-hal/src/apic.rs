//! Local APIC (Advanced Programmable Interrupt Controller) Driver

use crate::kprintln;

pub const APIC_BASE: usize = 0xFEE00000;

pub const APIC_REG_ID: usize = 0x020;
pub const APIC_REG_EOI: usize = 0x0B0;
pub const APIC_REG_SPURIOUS: usize = 0x0F0;
pub const APIC_REG_LVT_TIMER: usize = 0x320;
pub const APIC_REG_TIMER_INIT_COUNT: usize = 0x380;
pub const APIC_REG_TIMER_CURR_COUNT: usize = 0x390;
pub const APIC_REG_TIMER_DIVIDE: usize = 0x3E0;

#[inline(always)]
unsafe fn apic_read(reg: usize) -> u32 {
    let ptr = (APIC_BASE + reg) as *const u32;
    core::ptr::read_volatile(ptr)
}

#[inline(always)]
unsafe fn apic_write(reg: usize, val: u32) {
    let ptr = (APIC_BASE + reg) as *mut u32;
    core::ptr::write_volatile(ptr, val);
}

pub unsafe fn apic_eoi() {
    apic_write(APIC_REG_EOI, 0);
}

pub unsafe fn init() {
    // 1. Ensure Local APIC is globally enabled in IA32_APIC_BASE MSR (0x1B)
    let msr = crate::cpu::rdmsr(0x1B);
    crate::cpu::wrmsr(0x1B, msr | (1 << 11));

    // 2. Mask legacy 8259 PIC to prevent legacy IRQ collision
    crate::cpu::outb(0x21, 0xFF);
    crate::cpu::outb(0xA1, 0xFF);

    let apic_id = apic_read(APIC_REG_ID) >> 24;

    // 3. Enable APIC by setting bit 8 in Spurious Interrupt Vector Register (SVR)
    // and route spurious interrupts to vector 0xFF
    apic_write(APIC_REG_SPURIOUS, 0x1FF);

    // 4. Set Timer Divide configuration: divide by 16
    apic_write(APIC_REG_TIMER_DIVIDE, 0x03);

    // 5. Set LVT Timer: Periodic mode (bit 17 = 0x20000) on Vector 0x20
    apic_write(APIC_REG_LVT_TIMER, 0x20020);

    // 6. Initial counter value for periodic quantum ticks (smaller value for rapid initial ticks)
    apic_write(APIC_REG_TIMER_INIT_COUNT, 0x100000);

    kprintln!("[APIC] Local APIC online (CPU ID: {}, Vector: 0x20, Mode: Periodic)", apic_id);
}
