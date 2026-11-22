use core::sync::atomic::{AtomicU8, Ordering};

use purent_ntdef::composition::*;
use purent_ntdef::status::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};

use crate::mm::{
    virt_to_phys, vmm_map_user_page, vmm_unmap_user_page, ExAllocatePoolWithTag, ExFreePool,
    NonPagedPool, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};

use super::surface::{Rect, Surface};

const PAGE_SIZE: usize = 4096;
const IDLE: u8 = 0;
const REQUESTED: u8 = 1;
const FINISHED: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(IDLE);

pub struct Compositor {
    job: usize,
    pub console: Surface,
    pub dialog: Surface,
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
    pub unsafe fn prepare(frame: &Surface) -> Result<Self, NtStatus> {
        let size = frame.width as usize * frame.height as usize * 4;
        if size >= 0x1000_0000 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let surface_bytes = size.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let (job, allocation) =
            allocate_page_aligned(PAGE_SIZE + 2 * surface_bytes).ok_or(STATUS_NO_MEMORY)?;
        let console = job.add(PAGE_SIZE);
        let dialog = console.add(surface_bytes);
        let mappings = [
            (JOB_ADDRESS, job, PAGE_SIZE, false),
            (OUTPUT_ADDRESS, frame.buffer.cast(), surface_bytes, true),
            (CONSOLE_ADDRESS, console, surface_bytes, false),
            (DIALOG_ADDRESS, dialog, surface_bytes, false),
        ];
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
            console: Surface::from_raw(console.cast(), frame.width, frame.height, frame.width),
            dialog: Surface::from_raw(dialog.cast(), frame.width, frame.height, frame.width),
        })
    }

    pub fn compose(
        &mut self,
        area: Rect,
        console: Option<Rect>,
        console_opaque: Rect,
        dialog: Option<Rect>,
    ) {
        let screen = Rect::new(0, 0, self.console.width, self.console.height);
        let clipped = |rect: Option<Rect>| {
            rect.and_then(|rect| screen.intersect(&rect))
                .map_or_else(PixelRect::default, |rect| PixelRect {
                    left: rect.x as usize,
                    top: rect.y as usize,
                    right: rect.right() as usize,
                    bottom: rect.bottom() as usize,
                })
        };
        if screen.intersect(&area).is_none() {
            return;
        }
        let job = CompositionJob {
            width: screen.width as usize,
            height: screen.height as usize,
            dirty: clipped(Some(area)),
            console: clipped(console),
            console_opaque: clipped(Some(console_opaque)),
            dialog: clipped(dialog),
        };
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
