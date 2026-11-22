//! Interrupt Descriptor Table (IDT) and Exception Handling for AMD64

use core::arch::{asm, naked_asm};
use crate::kprintln;
use crate::cpu::{read_cr2, hlt_loop};

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    pub fn set_handler(&mut self, handler: usize) {
        self.selector = crate::gdt::KERNEL_CS;
        self.ist = 0;
        self.type_attr = 0x8E; // Present, Ring 0, 64-bit Interrupt Gate
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.zero = 0;
    }
}

#[repr(C, align(16))]
pub struct Idt {
    pub entries: [IdtEntry; 256],
}

#[repr(C, packed)]
struct IdtDescriptor {
    size: u16,
    offset: u64,
}

static mut IDT: Idt = Idt {
    entries: [IdtEntry::missing(); 256],
};

#[repr(C)]
#[derive(Debug)]
pub struct InterruptStackFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

pub static mut TIMER_TICKS: u64 = 0;
pub static mut TICK_CALLBACK: Option<unsafe fn()> = None;

pub unsafe fn register_tick_callback(cb: unsafe fn()) {
    TICK_CALLBACK = Some(cb);
}

pub unsafe fn init() {
    IDT.entries[0x00].set_handler(asm_divide_error as *const () as usize);
    IDT.entries[0x06].set_handler(asm_invalid_opcode as *const () as usize);
    IDT.entries[0x08].set_handler(asm_double_fault as *const () as usize);
    IDT.entries[0x0D].set_handler(asm_general_protection_fault as *const () as usize);
    IDT.entries[0x0E].set_handler(asm_page_fault as *const () as usize);
    IDT.entries[0x20].set_handler(asm_apic_timer as *const () as usize); // Vector 0x20: Local APIC Timer

    let idtr = IdtDescriptor {
        size: (core::mem::size_of::<Idt>() - 1) as u16,
        offset: &raw const IDT as u64,
    };

    asm!("lidt [{0}]", in(reg) &idtr, options(nostack, preserves_flags));
}

// Exception dispatcher functions called from assembly stubs
#[no_mangle]
pub unsafe extern "C" fn generic_exception_handler(vector: u64, error_code: u64, frame: *const InterruptStackFrame) {
    let f = &*frame;
    kprintln!("\n*** EXCEPTION: Vector 0x{:02X}, Error Code: 0x{:X}", vector, error_code);
    kprintln!("RIP: 0x{:016X}, CS: 0x{:04X}, RFLAGS: 0x{:016X}", f.rip, f.cs, f.rflags);
    kprintln!("RSP: 0x{:016X}, SS: 0x{:04X}", f.rsp, f.ss);

    kprintln!("Stack dump at RSP 0x{:016X}:", f.rsp);
    let sp = f.rsp as *const u64;
    for i in 0..16 {
        let val = core::ptr::read_unaligned(sp.add(i));
        kprintln!("  [RSP+0x{:02X}]: 0x{:016X}", i * 8, val);
    }

    if vector == 0x0E {
        kprintln!("CR2 (Faulting Address): 0x{:016X}", read_cr2());
    }

    kprintln!("[HAL] CPU halted due to fatal kernel exception.");
    hlt_loop();
}

#[no_mangle]
pub unsafe extern "C" fn apic_timer_handler() {
    core::ptr::write_volatile(&raw mut TIMER_TICKS, core::ptr::read_volatile(&raw const TIMER_TICKS) + 1);
    let ticks = core::ptr::read_volatile(&raw const TIMER_TICKS);
    if ticks <= 5 || ticks % 100 == 0 {
        kprintln!("[TIMER] Quantum Tick: {} (APIC interrupt)", ticks);
    }
    // Send EOI (End of Interrupt) to Local APIC at 0xFEE000B0
    let eoi_reg = 0xFEE000B0 as *mut u32;
    core::ptr::write_volatile(eoi_reg, 0);

    if let Some(cb) = TICK_CALLBACK {
        cb();
    }
}

// Assembly stubs for interrupts
macro_rules! interrupt_stub_no_err {
    ($name:ident, $vec:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push 0", // dummy error code
                "push rax", "push rcx", "push rdx", "push rsi", "push rdi", "push r8", "push r9", "push r10", "push r11",
                "sub rsp, 0x28", // 32 bytes Win64 shadow store + 8 bytes alignment
                "mov rcx, {vec}",
                "mov rdx, [rsp + 0x28 + 9 * 8]", // error code
                "lea r8, [rsp + 0x28 + 10 * 8]", // InterruptStackFrame pointer
                "call generic_exception_handler",
                "add rsp, 0x28",
                "pop r11", "pop r10", "pop r9", "pop r8", "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "add rsp, 8",
                "iretq",
                vec = const $vec,
            );
        }
    };
}

macro_rules! interrupt_stub_err {
    ($name:ident, $vec:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push rax", "push rcx", "push rdx", "push rsi", "push rdi", "push r8", "push r9", "push r10", "push r11",
                "sub rsp, 0x28", // 32 bytes Win64 shadow store + 8 bytes alignment
                "mov rcx, {vec}",
                "mov rdx, [rsp + 0x28 + 9 * 8]", // error code
                "lea r8, [rsp + 0x28 + 10 * 8]", // InterruptStackFrame pointer
                "call generic_exception_handler",
                "add rsp, 0x28",
                "pop r11", "pop r10", "pop r9", "pop r8", "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "add rsp, 8",
                "iretq",
                vec = const $vec,
            );
        }
    };
}

interrupt_stub_no_err!(asm_divide_error, 0x00);
interrupt_stub_no_err!(asm_invalid_opcode, 0x06);
interrupt_stub_err!(asm_double_fault, 0x08);
interrupt_stub_err!(asm_general_protection_fault, 0x0D);
interrupt_stub_err!(asm_page_fault, 0x0E);

#[unsafe(naked)]
unsafe extern "C" fn asm_apic_timer() {
    naked_asm!(
        "push rax", "push rcx", "push rdx", "push rsi", "push rdi", "push r8", "push r9", "push r10", "push r11",
        // Check if interrupted from Ring 3 (CS at [rsp + 9 * 8 + 8] = [rsp + 0x50])
        "test byte ptr [rsp + 0x50], 3",
        "jz 1f",
        "swapgs",
        "1:",
        "sub rsp, 0x20", // 32 bytes shadow store for Win64 ABI
        "call apic_timer_handler",
        "add rsp, 0x20",
        "test byte ptr [rsp + 0x50], 3",
        "jz 2f",
        "swapgs",
        "2:",
        "pop r11", "pop r10", "pop r9", "pop r8", "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
        "iretq",
    );
}
