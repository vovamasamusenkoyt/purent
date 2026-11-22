//! Fixed-size payload for the PureNT USER32 modal dialog service.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DialogText {
    pub title: [u8; 48],
    pub lines: [[u8; 48]; 3],
    pub button: [u8; 8],
}

impl DialogText {
    pub const fn new(title: &str, lines: [&str; 3], button: &str) -> Self {
        const fn field<const N: usize>(value: &str) -> [u8; N] {
            let mut bytes = [0; N];
            let mut i = 0;
            while i < value.len() && i < N {
                bytes[i] = value.as_bytes()[i];
                i += 1;
            }
            bytes
        }
        Self {
            title: field(title),
            lines: [field(lines[0]), field(lines[1]), field(lines[2])],
            button: field(button),
        }
    }
}
