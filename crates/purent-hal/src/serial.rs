//! 16550 UART Serial driver on COM1 (0x3F8)
//! Fully safe type abstraction over hardware port I/O

use core::fmt;
use crate::port::Port;

pub const COM1_BASE: u16 = 0x3F8;

pub struct SerialPort {
    data: Port<u8>,
    ier: Port<u8>,
    fcr: Port<u8>,
    lcr: Port<u8>,
    mcr: Port<u8>,
    lsr: Port<u8>,
}

unsafe impl Send for SerialPort {}
unsafe impl Sync for SerialPort {}

impl SerialPort {
    pub const fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            ier: Port::new(base + 1),
            fcr: Port::new(base + 2),
            lcr: Port::new(base + 3),
            mcr: Port::new(base + 4),
            lsr: Port::new(base + 5),
        }
    }

    pub fn init(&self) {
        self.ier.write(0x00); // Disable interrupts
        self.lcr.write(0x80); // Enable DLAB (set baud rate divisor)
        self.data.write(0x01); // Set divisor to 1 (115200 baud) - low byte
        self.ier.write(0x00); // high byte
        self.lcr.write(0x03); // 8 bits, no parity, one stop bit
        self.fcr.write(0xC7); // Enable FIFO, clear them, with 14-byte threshold
        self.mcr.write(0x0B); // IRQs enabled, RTS/DSR set
    }

    pub fn is_transmit_empty(&self) -> bool {
        (self.lsr.read() & 0x20) != 0
    }

    pub fn write_byte(&self, byte: u8) {
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        self.data.write(byte);
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
    let rflags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
        core::arch::asm!("cli", options(nomem, nostack));
    }
    let mut port = SerialPort::new(COM1_BASE);
    let _ = port.write_fmt(args);
    if (rflags & 0x200) != 0 {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}
