//! PS/2 Mouse Controller & Packet Driver (Intel 8042 Auxiliary Device)
//! Implements hardware initialization, packet streaming, and event polling for GUI desktop

use crate::cpu::{inb, outb};

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

#[derive(Copy, Clone, Debug, Default)]
pub struct MouseState {
    pub dx: i32,
    pub dy: i32,
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
}

static mut PACKET_CYCLE: usize = 0;
static mut PACKET_BYTES: [u8; 3] = [0; 3];

unsafe fn wait_write() {
    let mut timeout = 100_000;
    while (inb(STATUS_PORT) & 0x02) != 0 && timeout > 0 {
        core::hint::spin_loop();
        timeout -= 1;
    }
}

unsafe fn wait_read() -> bool {
    let mut timeout = 100_000;
    while (inb(STATUS_PORT) & 0x01) == 0 && timeout > 0 {
        core::hint::spin_loop();
        timeout -= 1;
    }
    timeout > 0
}

unsafe fn write_command(cmd: u8) {
    wait_write();
    outb(COMMAND_PORT, cmd);
}

unsafe fn write_mouse(byte: u8) {
    wait_write();
    outb(COMMAND_PORT, 0xD4); // Route next data byte to PS/2 auxiliary (mouse) port
    wait_write();
    outb(DATA_PORT, byte);
}

unsafe fn read_data() -> u8 {
    if wait_read() {
        inb(DATA_PORT)
    } else {
        0
    }
}

/// Initializes the 8042 PS/2 controller auxiliary device and activates mouse data reporting
pub unsafe fn ps2_mouse_init() {
    write_command(0xAE); // Enable the keyboard port.
    // 1. Enable auxiliary mouse device
    write_command(0xA8);

    // 2. Read controller config byte
    write_command(0x20);
    let mut config = read_data();

    // Poll both ports and translate keyboard scan codes to set 1.
    config = (config | 0x40) & !0x33;

    write_command(0x60);
    wait_write();
    outb(DATA_PORT, config);

    // 3. Set mouse to default configuration
    write_mouse(0xF6);
    let _ = read_data(); // ACK (0xFA)

    // 4. Enable data packet streaming
    write_mouse(0xF4);
    let _ = read_data(); // ACK (0xFA)
}

pub enum Ps2Input {
    Mouse(MouseState),
    Keyboard(u8),
    PartialMousePacket,
}

/// Reads one 8042 byte and routes it by the controller's auxiliary-device bit.
pub unsafe fn ps2_poll_input() -> Option<Ps2Input> {
    let status = inb(STATUS_PORT);
    if status & 0x01 == 0 {
        return None;
    }

    let b = inb(DATA_PORT);
    if status & 0x20 == 0 {
        return Some(Ps2Input::Keyboard(b));
    }

    match PACKET_CYCLE {
        0 => {
            // Byte 0 must have bit 3 set to 1 (sync bit)
            if (b & 0x08) != 0 {
                PACKET_BYTES[0] = b;
                PACKET_CYCLE = 1;
            }
        }
        1 => {
            PACKET_BYTES[1] = b;
            PACKET_CYCLE = 2;
        }
        2 => {
            PACKET_BYTES[2] = b;
            PACKET_CYCLE = 0;

            let flags = PACKET_BYTES[0];
            let raw_x = PACKET_BYTES[1];
            let raw_y = PACKET_BYTES[2];

            // Sign extension based on bits 4 (X) and 5 (Y)
            let dx = if (flags & 0x10) != 0 {
                (raw_x as i8) as i32
            } else {
                raw_x as i32
            };

            let dy = if (flags & 0x20) != 0 {
                (raw_y as i8) as i32
            } else {
                raw_y as i32
            };

            return Some(Ps2Input::Mouse(MouseState {
                dx,
                dy,
                left_button: (flags & 0x01) != 0,
                right_button: (flags & 0x02) != 0,
                middle_button: (flags & 0x04) != 0,
            }));
        }
        _ => {
            PACKET_CYCLE = 0;
        }
    }
    Some(Ps2Input::PartialMousePacket)
}
