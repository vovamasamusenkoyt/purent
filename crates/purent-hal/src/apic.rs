//! Local APIC (Advanced Programmable Interrupt Controller) Driver
//! Implements hardware timer calibration via 8254 PIT matching Windows NT HAL

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

/// Calibrate Local APIC timer ticks for a 10ms quantum (100 Hz) using the 8254 PIT Channel 2
unsafe fn calibrate_apic_via_pit() -> u32 {
    // 1. Prepare PIT Channel 2 (Port 0x61: Gate=0, Speaker=0)
    let port61 = crate::cpu::inb(0x61);
    crate::cpu::outb(0x61, port61 & 0xFC);

    // 2. Program PIT mode: Channel 2, LSB/MSB, Mode 0 (interrupt on terminal count)
    crate::cpu::outb(0x43, 0xB0);

    // 10ms delay: PIT frequency = 1,193,182 Hz -> 11,932 counts for 10ms
    let count = 11932u16;
    crate::cpu::outb(0x42, (count & 0xFF) as u8);
    crate::cpu::outb(0x42, (count >> 8) as u8);

    // 3. Set APIC timer to one-shot mode, divide by 16, start with 0xFFFFFFFF
    apic_write(APIC_REG_TIMER_DIVIDE, 0x03); // Divide by 16
    apic_write(APIC_REG_LVT_TIMER, 0x10020); // Masked, one-shot
    apic_write(APIC_REG_TIMER_INIT_COUNT, 0xFFFFFFFF);

    // 4. Start PIT timer by enabling Gate 2 (bit 0 of port 0x61)
    let p61 = crate::cpu::inb(0x61);
    crate::cpu::outb(0x61, (p61 & 0xFC) | 0x01);

    // 5. Wait until PIT Channel 2 counter reaches 0 (Port 0x61 bit 5 = OUT2 goes high)
    while (crate::cpu::inb(0x61) & 0x20) == 0 {
        core::hint::spin_loop();
    }

    // 6. Read remaining count in APIC
    let end_count = apic_read(APIC_REG_TIMER_CURR_COUNT);
    let ticks_per_10ms = 0xFFFFFFFFu32.wrapping_sub(end_count);

    // 7. Reset Port 0x61
    crate::cpu::outb(0x61, port61 & 0xFC);

    if ticks_per_10ms == 0 || ticks_per_10ms > 0x10000000 {
        0x20000 // Fallback default if calibration failed
    } else {
        ticks_per_10ms
    }
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

    // 4. Calibrate APIC Timer frequency using 8254 PIT
    let ticks_per_quantum = calibrate_apic_via_pit();
    kprintln!("[APIC] Calibrated Local APIC Timer via 8254 PIT: {} ticks/quantum (10ms @ 100 Hz)", ticks_per_quantum);

    // 5. Set Timer Divide configuration: divide by 16
    apic_write(APIC_REG_TIMER_DIVIDE, 0x03);

    // 6. Set LVT Timer: Periodic mode (bit 17 = 0x20000) on Vector 0x20
    apic_write(APIC_REG_LVT_TIMER, 0x20020);

    // 7. Initial counter value for calibrated 10ms quantum ticks
    apic_write(APIC_REG_TIMER_INIT_COUNT, ticks_per_quantum);

    kprintln!("[APIC] Local APIC online (CPU ID: {}, Vector: 0x20, Mode: Periodic 10ms)", apic_id);
}
