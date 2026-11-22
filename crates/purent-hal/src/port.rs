//! Type-safe x86_64 Port I/O abstraction

use core::marker::PhantomData;
use crate::cpu::{inb, inw, outb, outw};

pub trait PortReadWrite {
    unsafe fn read_from_port(port: u16) -> Self;
    unsafe fn write_to_port(port: u16, value: Self);
}

impl PortReadWrite for u8 {
    #[inline(always)]
    unsafe fn read_from_port(port: u16) -> Self {
        inb(port)
    }

    #[inline(always)]
    unsafe fn write_to_port(port: u16, value: Self) {
        outb(port, value)
    }
}

impl PortReadWrite for u16 {
    #[inline(always)]
    unsafe fn read_from_port(port: u16) -> Self {
        inw(port)
    }

    #[inline(always)]
    unsafe fn write_to_port(port: u16, value: Self) {
        outw(port, value)
    }
}

impl PortReadWrite for u32 {
    #[inline(always)]
    unsafe fn read_from_port(port: u16) -> Self {
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") val, options(nomem, nostack, preserves_flags));
        val
    }

    #[inline(always)]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Port<T: PortReadWrite> {
    port: u16,
    _phantom: PhantomData<T>,
}

impl<T: PortReadWrite> Port<T> {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: PhantomData,
        }
    }

    #[inline(always)]
    pub fn read(&self) -> T {
        unsafe { T::read_from_port(self.port) }
    }

    #[inline(always)]
    pub fn write(&self, value: T) {
        unsafe { T::write_to_port(self.port, value) }
    }
}
