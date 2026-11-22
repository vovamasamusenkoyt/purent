#![no_std]

pub mod apic;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod serial;

pub use apic::init as apic_init;
pub use cpu::*;
pub use gdt::*;
pub use idt::{init as idt_init, register_tick_callback};
pub use serial::*;
