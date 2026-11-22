//! Physical Memory Manager (PMM)
//! Manages raw physical page frames, bitmap allocator, and UEFI boot reclamation.

use purent_hal::kprintln;
use purent_ntdef::loader::PureNtLoaderBlock;

pub const PAGE_SIZE: usize = 4096;
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;

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

        let mut total_ram_pages = 0usize;
        let mut max_phys_addr = 0u64;

        // Scan memory map for physical RAM boundaries (types 1..4 and 7: Loader, BootServices, Conventional)
        for i in 0..entries {
            let desc = &*(map_addr.wrapping_add(i * desc_size) as *const EfiMemoryDescriptor);
            let is_ram = desc.r#type == 1
                || desc.r#type == 2
                || desc.r#type == 3
                || desc.r#type == 4
                || desc.r#type == 7;

            if is_ram {
                total_ram_pages += desc.number_of_pages as usize;
                let end_addr = desc.physical_start + desc.number_of_pages * (PAGE_SIZE as u64);
                if end_addr > max_phys_addr {
                    max_phys_addr = end_addr;
                }
            }
        }

        let max_frame = (max_phys_addr as usize) / PAGE_SIZE;
        self.total_pages = total_ram_pages;
        self.bitmap_words = (max_frame + 63) / 64;
        if self.bitmap_words > 16384 {
            self.bitmap_words = 16384;
        }
        self.bitmap_ptr = &raw mut PMM_STORAGE.0 as *mut u64;

        // Mark all pages as used
        for i in 0..self.bitmap_words {
            *self.bitmap_ptr.add(i) = !0;
        }

        // Mark available memory regions as free (Conventional RAM + Reclaimed BootServices)
        let mut free_count = 0usize;
        for i in 0..entries {
            let desc = &*(map_addr.wrapping_add(i * desc_size) as *const EfiMemoryDescriptor);
            let is_available = desc.r#type == EFI_CONVENTIONAL_MEMORY
                || desc.r#type == EFI_BOOT_SERVICES_CODE
                || desc.r#type == EFI_BOOT_SERVICES_DATA;

            if is_available {
                let start_frame = (desc.physical_start as usize) / PAGE_SIZE;
                let frame_count = desc.number_of_pages as usize;

                for f in 0..frame_count {
                    let frame = start_frame + f;
                    // Protect first 16MB (where low memory, kernel, and initial boot pool live: 0x000000..0x01000000)
                    if frame >= 4096 && frame < max_frame {
                        let word = frame / 64;
                        let bit = frame % 64;
                        if word < self.bitmap_words {
                            *self.bitmap_ptr.add(word) &= !(1u64 << bit);
                            free_count += 1;
                        }
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
