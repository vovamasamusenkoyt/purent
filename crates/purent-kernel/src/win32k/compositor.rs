use core::sync::atomic::{AtomicU8, Ordering};

use purent_ntdef::composition::*;
use purent_ntdef::status::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};

use crate::mm::{
    virt_to_phys, vmm_map_user_page, vmm_unmap_user_page, ExAllocatePoolWithTag, ExFreePool,
    NonPagedPool, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};

use super::{dialog, windows::{self, DesktopWindow}, surface::{Rect, Surface}};

const PAGE_SIZE: usize = 4096;
const IDLE: u8 = 0;
const REQUESTED: u8 = 1;
const FINISHED: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(IDLE);

pub struct Compositor {
    job: usize,
    pub console: Surface,
    pub windows: [Surface; MAX_WINDOW_SURFACES],
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
        let window_bytes = rounded_size(windows::MAX_WIDTH, windows::MAX_HEIGHT);
        let (job, allocation) = allocate_page_aligned(
            PAGE_SIZE + console_bytes + MAX_WINDOW_SURFACES * window_bytes,
        ).ok_or(STATUS_NO_MEMORY)?;
        let console = job.add(PAGE_SIZE);
        let windows = console.add(console_bytes);
        let mut mappings = [(0, job, 0, false); MAX_LAYERS + 2];
        mappings[0] = (JOB_ADDRESS, job, PAGE_SIZE, false);
        mappings[1] = (OUTPUT_ADDRESS, frame.buffer.cast(), frame_bytes, true);
        mappings[2] = (surface_address(0), console, console_bytes, false);
        for slot in 0..MAX_WINDOW_SURFACES {
            mappings[slot + 3] = (
                surface_address(slot + 1), windows.add(slot * window_bytes), window_bytes, false,
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
            windows: core::array::from_fn(|slot| {
                Surface::from_raw(windows.add(slot * window_bytes).cast(),
                    windows::MAX_WIDTH, windows::MAX_HEIGHT, windows::MAX_WIDTH)
            }),
        })
    }

    pub fn draw_window(&mut self, window: &DesktopWindow, active: bool) {
        let rect = Rect::new(0, 0, window.rect.width, window.rect.height);
        window.draw(&mut self.windows[window.slot], rect, true, active);
    }

    pub fn compose(
        &mut self,
        screen: Rect,
        area: Rect,
        console: Option<(Rect, Rect)>,
        windows: &[Option<DesktopWindow>; MAX_WINDOW_SURFACES],
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
        let mut push = |rect: Rect, slot: usize, stride: usize, opaque: Option<Rect>| {
            if screen.intersect(&rect).is_some() {
                job.layers[job.layer_count] = WindowLayer {
                    bounds: clipped(rect),
                    opaque: opaque.map_or_else(PixelRect::default, clipped),
                    origin_x: rect.x,
                    origin_y: rect.y,
                    stride,
                    slot,
                    glass: opaque.is_some(),
                };
                job.layer_count += 1;
            }
        };
        if let Some((rect, opaque)) = console {
            push(rect, 0, self.console.stride as usize, Some(opaque));
        }
        for window in windows.iter().flatten().filter(|window| window.visible()) {
            push(window.rect, window.slot + 1, self.windows[window.slot].stride as usize, Some(dialog::client(window.rect)));
        }
        purent_hal::kprintln!("[WIN32K-COMPOSITOR] compose called: layers={}, dirty=({},{},{},{})",
            job.layer_count, job.dirty.left, job.dirty.top, job.dirty.right, job.dirty.bottom);
        for i in 0..job.layer_count {
            let l = &job.layers[i];
            purent_hal::kprintln!("[WIN32K-COMPOSITOR] layer {}: bounds=({},{},{},{}), slot={}",
                i, l.bounds.left, l.bounds.top, l.bounds.right, l.bounds.bottom, l.slot);
        }
        let w0_p = unsafe { (self.windows[0].buffer as *const u32).add(70 * 520 + 100).read() };
        let w1_p = unsafe { (self.windows[1].buffer as *const u32).add(70 * 520 + 100).read() };
        purent_hal::kprintln!("[WIN32K-COMPOSITOR] window 0 client center=0x{:08X}, window 1 client center=0x{:08X}", w0_p, w1_p);
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
