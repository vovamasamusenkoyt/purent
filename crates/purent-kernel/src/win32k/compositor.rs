use core::sync::atomic::{AtomicU8, Ordering};

use purent_ntdef::composition::*;
use purent_ntdef::status::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};

use crate::mm::{
    virt_to_phys, vmm_map_user_page, vmm_unmap_user_page, ExAllocatePoolWithTag, ExFreePool,
    NonPagedPool, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};

use super::{dialog, surface::{Rect, Surface}};

const PAGE_SIZE: usize = 4096;
const IDLE: u8 = 0;
const REQUESTED: u8 = 1;
const FINISHED: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(IDLE);

pub struct Compositor {
    job: usize,
    pub console: Surface,
    pub dialogs: [Surface; MAX_DIALOG_SURFACES],
}

pub unsafe fn allocate_page_aligned(bytes: usize) -> Option<(*mut u8, *mut core::ffi::c_void)> {
    let length = bytes.checked_add(2 * (PAGE_SIZE - 1))?;
    let allocation = ExAllocatePoolWithTag(NonPagedPool, length, u32::from_le_bytes(*b"DwmS"));
    if allocation.is_null() {
        return None;
    }
    let aligned = (allocation as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    Some((aligned as *mut u8, allocation))
}

impl Compositor {
    pub unsafe fn prepare(frame: &Surface, window: Rect) -> Result<Self, NtStatus> {
        let size = frame.width as usize * frame.height as usize * 4;
        if size >= 0x1000_0000 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let frame_bytes = size.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let rounded_size = |width: u32, height: u32| {
            (width as usize * height as usize * 4).div_ceil(PAGE_SIZE) * PAGE_SIZE
        };
        let console_bytes = rounded_size(window.width, window.height);
        let dialog_bytes = rounded_size(dialog::WIDTH, dialog::HEIGHT);
        let (job, allocation) = allocate_page_aligned(
            PAGE_SIZE + console_bytes + MAX_DIALOG_SURFACES * dialog_bytes,
        ).ok_or(STATUS_NO_MEMORY)?;
        let console = job.add(PAGE_SIZE);
        let dialogs = console.add(console_bytes);
        let mut mappings = [(0, job, 0, false); MAX_LAYERS + 2];
        mappings[0] = (JOB_ADDRESS, job, PAGE_SIZE, false);
        mappings[1] = (OUTPUT_ADDRESS, frame.buffer.cast(), frame_bytes, true);
        mappings[2] = (surface_address(0), console, console_bytes, false);
        for slot in 0..MAX_DIALOG_SURFACES {
            mappings[slot + 3] = (
                surface_address(slot + 1), dialogs.add(slot * dialog_bytes), dialog_bytes, false,
            );
        }
        let cr3 = purent_hal::cpu::read_cr3();
        for (index, &(alias, ptr, len, writable)) in mappings.iter().enumerate() {
            let flags = PTE_USER | PTE_PRESENT | PTE_NX | if writable { PTE_WRITABLE } else { 0 };
            let phys = virt_to_phys(ptr);
            for offset in (0..len).step_by(PAGE_SIZE) {
                if let Err(status) =
                    vmm_map_user_page(cr3, alias + offset as u64, phys + offset as u64, flags)
                {
                    for (previous, &(base, _, len, _)) in mappings[..=index].iter().enumerate() {
                        let mapped = if previous == index { offset } else { len };
                        for offset in (0..mapped).step_by(PAGE_SIZE) {
                            vmm_unmap_user_page(cr3, base + offset as u64);
                        }
                    }
                    ExFreePool(allocation);
                    return Err(status);
                }
            }
        }
        Ok(Self {
            job: job as usize,
            console: Surface::from_raw(console.cast(), window.width, window.height, window.width),
            dialogs: core::array::from_fn(|slot| {
                Surface::from_raw(dialogs.add(slot * dialog_bytes).cast(),
                    dialog::WIDTH, dialog::HEIGHT, dialog::WIDTH)
            }),
        })
    }

    pub fn draw_dialog(&mut self, window: &dialog::Dialog, active: bool) {
        let rect = Rect::new(0, 0, dialog::WIDTH, dialog::HEIGHT);
        dialog::draw(&mut self.dialogs[window.slot], rect, &window.text, true, active);
    }

    pub fn compose(
        &mut self,
        screen: Rect,
        area: Rect,
        console: Option<(Rect, Rect)>,
        dialogs: &[Option<dialog::Dialog>; MAX_DIALOG_SURFACES],
    ) {
        let clipped = |rect: Rect| {
            screen.intersect(&rect).map_or_else(PixelRect::default, |rect| PixelRect {
                left: rect.x as usize,
                top: rect.y as usize,
                right: rect.right() as usize,
                bottom: rect.bottom() as usize,
            })
        };
        if screen.intersect(&area).is_none() {
            return;
        }
        let mut job = CompositionJob {
            width: screen.width as usize,
            height: screen.height as usize,
            dirty: clipped(area),
            layer_count: 0,
            layers: [WindowLayer::default(); MAX_LAYERS],
        };
        let mut push = |rect: Rect, slot: usize, opaque: Option<Rect>| {
            if screen.intersect(&rect).is_some() {
                job.layers[job.layer_count] = WindowLayer {
                    bounds: clipped(rect),
                    opaque: opaque.map_or_else(PixelRect::default, clipped),
                    origin_x: rect.x,
                    origin_y: rect.y,
                    stride: rect.width as usize,
                    slot,
                    glass: opaque.is_some(),
                };
                job.layer_count += 1;
            }
        };
        if let Some((rect, opaque)) = console {
            push(rect, 0, Some(opaque));
        }
        for window in dialogs.iter().flatten() {
            push(window.rect, window.slot + 1, Some(dialog::client(window.rect)));
        }
        unsafe { core::ptr::write(self.job as *mut CompositionJob, job) };
        STATE.store(REQUESTED, Ordering::Release);
        while STATE.load(Ordering::Acquire) != FINISHED {
            unsafe { purent_hal::cpu::halt() };
        }
        STATE.store(IDLE, Ordering::Release);
    }
}

pub fn receive() -> NtStatus {
    if crate::ps::current_process_id() != Some(super::DWM_PID) {
        return STATUS_ACCESS_DENIED;
    }
    while STATE.load(Ordering::Acquire) != REQUESTED {
        unsafe { purent_hal::cpu::halt() };
    }
    STATUS_SUCCESS
}

pub fn finish() -> NtStatus {
    if crate::ps::current_process_id() != Some(super::DWM_PID) {
        return STATUS_ACCESS_DENIED;
    }
    if STATE
        .compare_exchange(REQUESTED, FINISHED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
