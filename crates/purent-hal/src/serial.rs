//! 16550 UART Serial driver on COM1 (0x3F8)

use core::fmt;
use crate::cpu::{inb, outb};

pub const COM1_BASE: u16 = 0x3F8;

pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    pub unsafe fn init(&self) {
        outb(self.base + 1, 0x00); // Disable interrupts
        outb(self.base + 3, 0x80); // Enable DLAB (set baud rate divisor)
        outb(self.base + 0, 0x01); // Set divisor to 1 (115200 baud) - low byte
        outb(self.base + 1, 0x00); // high byte
        outb(self.base + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(self.base + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold
        outb(self.base + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }

    fn line_status(&self) -> u8 {
        unsafe { inb(self.base + 5) }
    }

    pub fn is_transmit_empty(&self) -> bool {
        (self.line_status() & 0x20) != 0
    }

    pub fn write_byte(&self, byte: u8) {
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        unsafe {
            outb(self.base, byte);
        }
    }

    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        SerialPort::write_str(self, s);
        Ok(())
    }
}

pub static SERIAL1: SerialPort = SerialPort::new(COM1_BASE);

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}

pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut port = SerialPort::new(COM1_BASE);
    let _ = port.write_fmt(args);
}
