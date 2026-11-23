//! Shared work descriptor for the PureNT desktop compositor.

pub const JOB_ADDRESS: u64 = 0x0100_0000_0000;
pub const OUTPUT_ADDRESS: u64 = JOB_ADDRESS + 0x1000_0000;
pub const SURFACE_ADDRESS: u64 = JOB_ADDRESS + 0x2000_0000;
pub const SLOT_BYTES: u64 = 0x1000_0000;
pub const MAX_DIALOG_SURFACES: usize = 4;
pub const MAX_LAYERS: usize = 1 + MAX_DIALOG_SURFACES;

pub const fn surface_address(slot: usize) -> u64 {
    SURFACE_ADDRESS + slot as u64 * SLOT_BYTES
}

pub const GLASS_PIXEL: u32 = 0;

/// Composite straight-alpha foreground onto an opaque background.
pub fn blend_over(foreground: u32, background: u32) -> u32 {
    let alpha = foreground >> 24;
    if alpha == 255 {
        return foreground;
    }
    if alpha == 0 {
        return background;
    }
    let channel = |shift: u32| {
        let source = (foreground >> shift) & 255;
        let target = (background >> shift) & 255;
        ((source * alpha + target * (255 - alpha) + 127) / 255) << shift
    };
    0xFF00_0000 | channel(16) | channel(8) | channel(0)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PixelRect {
    pub left: usize,
    pub top: usize,
    pub right: usize,
    pub bottom: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WindowLayer {
    pub bounds: PixelRect,
    pub opaque: PixelRect,
    pub origin_x: i32,
    pub origin_y: i32,
    pub stride: usize,
    pub slot: usize,
    pub glass: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompositionJob {
    pub width: usize,
    pub height: usize,
    pub dirty: PixelRect,
    /// Back to front, with each source positioned in desktop coordinates.
    pub layer_count: usize,
    pub layers: [WindowLayer; MAX_LAYERS],
}

const _: () = assert!(core::mem::size_of::<CompositionJob>() <= 4096);
