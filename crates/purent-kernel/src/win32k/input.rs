//! Set 1 keyboard decoding and the console's single-producer input queue.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use purent_ntdef::syscall::{CONSOLE_LINE_CAPACITY, CONSOLE_OUTPUT_LENGTH_SHIFT};

pub static KEYBOARD_INPUT: InputQueue<128> = InputQueue::new();
pub static CONSOLE_INPUT: InputQueue<{ CONSOLE_LINE_CAPACITY + 1 }> = InputQueue::new();

pub static CONSOLE_OUTPUT: InputQueue<4097> = InputQueue::new();

pub fn read_output_packet() -> u64 {
    let mut packet = 0u64;
    let mut len = 0;
    while len < 3 {
        let Some(byte) = CONSOLE_OUTPUT.pop() else {
            break;
        };
        packet |= u64::from(byte) << (len * 8);
        len += 1;
    }
    packet | (len << CONSOLE_OUTPUT_LENGTH_SHIFT)
}

pub fn wait_host_event() -> u64 {
    loop {
        let output = read_output_packet();
        if output != 0 {
            return output;
        }
        if let Some(key) = KEYBOARD_INPUT.pop() {
            return key.into();
        }
        unsafe { purent_hal::cpu::halt() };
    }
}

pub struct InputQueue<const CAPACITY: usize> {
    input: [AtomicU8; CAPACITY],
    read: AtomicUsize,
    write: AtomicUsize,
}

impl<const CAPACITY: usize> InputQueue<CAPACITY> {
    const fn new() -> Self {
        Self {
            input: [const { AtomicU8::new(0) }; CAPACITY],
            read: AtomicUsize::new(0),
            write: AtomicUsize::new(0),
        }
    }

    pub fn pop(&self) -> Option<u8> {
        let read = self.read.load(Ordering::Relaxed);
        if read == self.write.load(Ordering::Acquire) {
            return None;
        }
        let value = self.input[read].load(Ordering::Relaxed);
        self.read.store((read + 1) % CAPACITY, Ordering::Release);
        Some(value)
    }

    pub fn push(&self, ch: u8) -> bool {
        let write = self.write.load(Ordering::Relaxed);
        let next = (write + 1) % CAPACITY;
        if next == self.read.load(Ordering::Acquire) {
            return false;
        }
        self.input[write].store(ch, Ordering::Relaxed);
        self.write.store(next, Ordering::Release);
        true
    }

    pub fn wait_pop(&self) -> u8 {
        loop {
            if let Some(byte) = self.pop() {
                return byte;
            }
            // Called from syscall dispatch with interrupts enabled.
            unsafe { purent_hal::cpu::halt() };
        }
    }
}

#[derive(Default)]
pub struct Keyboard {
    left_shift: bool,
    right_shift: bool,
    caps_lock: bool,
    caps_pressed: bool,
    extended: bool,
    pause_bytes: u8,
}

impl Keyboard {
    pub fn decode(&mut self, scan: u8) -> Option<u8> {
        if self.pause_bytes != 0 {
            self.pause_bytes -= 1;
            return None;
        }
        match scan {
            0xE0 => {
                self.extended = true;
                return None;
            }
            0xE1 => {
                self.extended = false;
                self.pause_bytes = 5;
                return None;
            }
            _ => {}
        }
        let pressed = scan & 0x80 == 0;
        let key = scan & 0x7F;
        if core::mem::take(&mut self.extended) {
            return (pressed && key == 0x1C).then_some(b'\r');
        }
        match key {
            0x2A => self.left_shift = pressed,
            0x36 => self.right_shift = pressed,
            0x3A => {
                if pressed && !self.caps_pressed {
                    self.caps_lock = !self.caps_lock;
                }
                self.caps_pressed = pressed;
            }
            _ if pressed => {
                let shift = self.left_shift || self.right_shift;
                return match key {
                    0x01 => Some(27),
                    0x0E => Some(8),
                    0x0F => Some(b'\t'),
                    0x1C => Some(b'\r'),
                    0x39 => Some(b' '),
                    0x02..=0x0D => Some(
                        if shift {
                            b"!@#$%^&*()_+"
                        } else {
                            b"1234567890-="
                        }[(key - 2) as usize],
                    ),
                    0x10..=0x1B => Some(ascii_key(
                        key - 0x10,
                        b"qwertyuiop[]",
                        b"QWERTYUIOP{}",
                        shift,
                        self.caps_lock,
                    )),
                    0x1E..=0x29 => Some(ascii_key(
                        key - 0x1E,
                        b"asdfghjkl;'`",
                        br#"ASDFGHJKL:"~"#,
                        shift,
                        self.caps_lock,
                    )),
                    0x2B => Some(if shift { b'|' } else { b'\\' }),
                    0x2C..=0x35 => Some(ascii_key(
                        key - 0x2C,
                        b"zxcvbnm,./",
                        b"ZXCVBNM<>?",
                        shift,
                        self.caps_lock,
                    )),
                    _ => None,
                };
            }
            _ => {}
        }
        None
    }
}

fn ascii_key(index: u8, plain: &[u8], shifted: &[u8], shift: bool, caps: bool) -> u8 {
    let index = index as usize;
    let ch = plain[index];
    if shift ^ (caps && ch.is_ascii_alphabetic()) {
        shifted[index]
    } else {
        ch
    }
}
