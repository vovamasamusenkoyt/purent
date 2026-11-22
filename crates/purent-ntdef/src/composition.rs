//! Shared work descriptor for the PureNT desktop compositor.

pub const JOB_ADDRESS: u64 = 0x0100_0000_0000;
pub const OUTPUT_ADDRESS: u64 = JOB_ADDRESS + 0x1000_0000;
pub const CONSOLE_ADDRESS: u64 = JOB_ADDRESS + 0x2000_0000;
pub const DIALOG_ADDRESS: u64 = JOB_ADDRESS + 0x3000_0000;

pub const GLASS_PIXEL: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PixelRect {
    pub left: usize,
    pub top: usize,
    pub right: usize,
    pub bottom: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompositionJob {
    pub width: usize,
    pub height: usize,
    pub dirty: PixelRect,
    pub console: PixelRect,
    pub console_opaque: PixelRect,
    pub dialog: PixelRect,
}
