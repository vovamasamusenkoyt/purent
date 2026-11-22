//! Physical Memory Manager (PMM) and Non-Paged Pool Allocator

use purent_hal::kprintln;
use purent_ntdef::loader::PureNtLoaderBlock;

pub const PAGE_SIZE: usize = 4096;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const POOL_TAG_NONE: u32 = 0x656E6F4E; // "None"

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EfiMemoryDescriptor {
    pub r#type: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

pub struct PhysicalMemoryManager {
    total_pages: usize,
    free_pages: usize,
    bitmap_ptr: *mut u64,
    bitmap_words: usize,
}

unsafe impl Send for PhysicalMemoryManager {}

pub static PMM: purent_hal::SpinLock<PhysicalMemoryManager> = purent_hal::SpinLock::new(PhysicalMemoryManager {
    total_pages: 0,
    free_pages: 0,
    bitmap_ptr: core::ptr::null_mut(),
    bitmap_words: 0,
});

// Static storage for PMM frame tracking (up to 4GB of physical RAM = 1,048,576 pages = 16,384 u64 words = 128 KiB)
#[repr(align(4096))]
struct PmmStorage([u64; 16384]);
static mut PMM_STORAGE: PmmStorage = PmmStorage([!0; 16384]); // Start with all pages marked as used (1 = used)

impl PhysicalMemoryManager {
    pub unsafe fn init(&mut self, ldr: &PureNtLoaderBlock) {
        let desc_size = ldr.memory_map_desc_size as usize;
        let entries = ldr.memory_map_entries as usize;
        let map_addr = ldr.memory_map_addr as usize;

        let mut max_phys_addr = 0u64;

        // Scan memory map
        for i in 0..entries {
            let desc = &*(map_addr.wrapping_add(i * desc_size) as *const EfiMemoryDescriptor);
            let end_addr = desc.physical_start + desc.number_of_pages * (PAGE_SIZE as u64);
            if end_addr > max_phys_addr {
                max_phys_addr = end_addr;
            }
        }

        self.total_pages = (max_phys_addr as usize) / PAGE_SIZE;
        if self.total_pages > 16384 * 64 {
            self.total_pages = 16384 * 64;
        }
        self.bitmap_words = (self.total_pages + 63) / 64;
        self.bitmap_ptr = &raw mut PMM_STORAGE.0 as *mut u64;

        // Mark all pages as used
        for i in 0..self.bitmap_words {
            *self.bitmap_ptr.add(i) = !0;
        }

        // Mark conventional free memory regions as available (0 = free)
        let mut free_count = 0usize;
        for i in 0..entries {
            let desc = &*(map_addr.wrapping_add(i * desc_size) as *const EfiMemoryDescriptor);
            if desc.r#type == EFI_CONVENTIONAL_MEMORY {
                let start_frame = (desc.physical_start as usize) / PAGE_SIZE;
                let frame_count = desc.number_of_pages as usize;

                for f in 0..frame_count {
                    let frame = start_frame + f;
                    // Protect first 4MB (where kernel, boot structures, and low memory live)
                    if frame >= 1024 && frame < self.total_pages {
                        let word = frame / 64;
                        let bit = frame % 64;
                        *self.bitmap_ptr.add(word) &= !(1u64 << bit);
                        free_count += 1;
                    }
                }
            }
        }

        self.free_pages = free_count;
        kprintln!("[PMM] Physical Memory Initialized: {} MiB free / {} MiB total",
            (free_count * PAGE_SIZE) / (1024 * 1024),
            (self.total_pages * PAGE_SIZE) / (1024 * 1024)
        );
    }

    pub unsafe fn allocate_frame(&mut self) -> Option<u64> {
        for word_idx in 0..self.bitmap_words {
            let word = *self.bitmap_ptr.add(word_idx);
            if word != !0 {
                // Found a word with at least one free frame (bit = 0)
                let bit_idx = (!word).trailing_zeros() as usize;
                let frame = word_idx * 64 + bit_idx;
                if frame < self.total_pages {
                    *self.bitmap_ptr.add(word_idx) |= 1u64 << bit_idx;
                    self.free_pages -= 1;
                    return Some((frame * PAGE_SIZE) as u64);
                }
            }
        }
        None
    }

    pub unsafe fn free_frame(&mut self, phys_addr: u64) {
        let frame = (phys_addr as usize) / PAGE_SIZE;
        if frame < self.total_pages {
            let word_idx = frame / 64;
            let bit_idx = frame % 64;
            *self.bitmap_ptr.add(word_idx) &= !(1u64 << bit_idx);
            self.free_pages += 1;
        }
    }
}

pub fn pmm_init(ldr: &PureNtLoaderBlock) {
    unsafe {
        PMM.lock().init(ldr);
    }
}

// ------------------------------------------------------------------------------------------------
// Non-Paged Pool (Kernel Dynamic Heap Allocator)
// ------------------------------------------------------------------------------------------------

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
        // Allocate initial 1MB virtual heap window from physical memory
        // In PureNT, 0xFFFFF80000000000 + phys is mapped 1:1 in higher-half
        let mut pmm = PMM.lock();
        if let Some(phys) = pmm.allocate_frame() {
            let virt = 0xFFFFF80000000000usize + (phys as usize);
            self.heap_curr = virt;
            self.heap_end = virt + PAGE_SIZE;

            // Pre-allocate 31 more pages (total 128 KiB heap buffer)
            for _ in 0..31 {
                if let Some(p) = pmm.allocate_frame() {
                    let v = 0xFFFFF80000000000usize + (p as usize);
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
        // Align allocation to 16 bytes
        size = (size + 15) & !15;
        let total_size = header_size + size;

        while self.heap_curr + total_size > self.heap_end {
            // Expand heap with a new physical page
            let mut pmm = PMM.lock();
            if let Some(phys) = pmm.allocate_frame() {
                let virt = 0xFFFFF80000000000usize + (phys as usize);
                if self.heap_end == 0 || virt == self.heap_end {
                    self.heap_end += PAGE_SIZE;
                } else {
                    // Discontiguous page: reset bump pointer to new page
                    self.heap_curr = virt;
                    self.heap_end = virt + PAGE_SIZE;
                }
            } else {
                return core::ptr::null_mut(); // Out of memory
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

// ------------------------------------------------------------------------------------------------
// NT Kernel Memory Export APIs
// ------------------------------------------------------------------------------------------------

#[allow(non_upper_case_globals)]
pub const NonPagedPool: u32 = 0;
#[allow(non_upper_case_globals)]
pub const PagedPool: u32 = 1;
#[allow(non_upper_case_globals)]
pub const NonPagedPoolMustSucceed: u32 = 2;

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
