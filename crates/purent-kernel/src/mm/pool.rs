//! Non-Paged Pool (Kernel Dynamic Heap Allocator)
//! Implements tag-based kernel memory allocation (`ExAllocatePoolWithTag`, `ExFreePoolWithTag`).

use purent_hal::kprintln;
use super::pmm::{PMM, PAGE_SIZE};
use super::vmm::PHYSICAL_MAP_BASE;

pub const POOL_TAG_NONE: u32 = 0x656E6F4E; // "None"

#[allow(non_upper_case_globals)]
pub const NonPagedPool: u32 = 0;
#[allow(non_upper_case_globals)]
pub const PagedPool: u32 = 1;
#[allow(non_upper_case_globals)]
pub const NonPagedPoolMustSucceed: u32 = 2;

#[repr(C)]
struct PoolHeader {
    size: usize,
    tag: u32,
    free: u32,
}

pub struct NonPagedPool {
    heap_curr: usize,
    heap_end: usize,
}

unsafe impl Send for NonPagedPool {}

pub static KERNEL_POOL: purent_hal::SpinLock<NonPagedPool> = purent_hal::SpinLock::new(NonPagedPool {
    heap_curr: 0,
    heap_end: 0,
});

impl NonPagedPool {
    pub unsafe fn init(&mut self) {
        // Allocate initial 128 KiB heap buffer from physical memory mapped 1:1 in higher-half
        let mut pmm = PMM.lock();
        if let Some(phys) = pmm.allocate_frame() {
            let virt = (PHYSICAL_MAP_BASE + phys) as usize;
            self.heap_curr = virt;
            self.heap_end = virt + PAGE_SIZE;

            for _ in 0..31 {
                if let Some(p) = pmm.allocate_frame() {
                    let v = (PHYSICAL_MAP_BASE + p) as usize;
                    if v == self.heap_end {
                        self.heap_end += PAGE_SIZE;
                    }
                }
            }

            kprintln!("[POOL] NonPagedPool online at 0x{:016X} (initial buffer: {} KiB)",
                self.heap_curr,
                (self.heap_end - self.heap_curr) / 1024
            );
        }
    }

    pub unsafe fn allocate(&mut self, mut size: usize, tag: u32) -> *mut u8 {
        let header_size = core::mem::size_of::<PoolHeader>();
        size = (size + 15) & !15;
        let total_size = header_size + size;

        while self.heap_curr + total_size > self.heap_end {
            let mut pmm = PMM.lock();
            if let Some(phys) = pmm.allocate_frame() {
                let virt = (PHYSICAL_MAP_BASE + phys) as usize;
                if self.heap_end == 0 || virt == self.heap_end {
                    self.heap_end += PAGE_SIZE;
                } else {
                    self.heap_curr = virt;
                    self.heap_end = virt + PAGE_SIZE;
                }
            } else {
                return core::ptr::null_mut();
            }
        }

        let header_ptr = self.heap_curr as *mut PoolHeader;
        (*header_ptr).size = size;
        (*header_ptr).tag = tag;
        (*header_ptr).free = 0;

        let payload_ptr = (self.heap_curr + header_size) as *mut u8;
        self.heap_curr += total_size;
        payload_ptr
    }
}

pub fn pool_init() {
    unsafe {
        KERNEL_POOL.lock().init();
    }
}

#[no_mangle]
pub unsafe extern "win64" fn ExAllocatePoolWithTag(
    _pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    let ptr = KERNEL_POOL.lock().allocate(number_of_bytes, tag);
    ptr as *mut core::ffi::c_void
}

#[no_mangle]
pub unsafe extern "win64" fn ExAllocatePool(
    pool_type: u32,
    number_of_bytes: usize,
) -> *mut core::ffi::c_void {
    ExAllocatePoolWithTag(pool_type, number_of_bytes, POOL_TAG_NONE)
}

#[no_mangle]
pub unsafe extern "win64" fn ExFreePoolWithTag(
    p: *mut core::ffi::c_void,
    _tag: u32,
) {
    if p.is_null() {
        return;
    }
    let header_size = core::mem::size_of::<PoolHeader>();
    let header_ptr = (p as usize - header_size) as *mut PoolHeader;
    (*header_ptr).free = 1;
}

#[no_mangle]
pub unsafe extern "win64" fn ExFreePool(p: *mut core::ffi::c_void) {
    ExFreePoolWithTag(p, 0);
}
