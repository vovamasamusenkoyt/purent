//! Physical Memory Manager (PMM), Virtual Memory Manager (VMM), and Non-Paged Pool Allocator

use purent_hal::kprintln;
use purent_ntdef::loader::PureNtLoaderBlock;
use purent_ntdef::status::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use core::sync::atomic::{AtomicUsize, Ordering};

pub const PAGE_SIZE: usize = 4096;
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const POOL_TAG_NONE: u32 = 0x656E6F4E; // "None"

pub const PHYSICAL_MAP_BASE: u64 = 0xFFFFF80000000000;

#[inline(always)]
pub unsafe fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYSICAL_MAP_BASE + phys) as *mut T
}

#[inline(always)]
pub unsafe fn virt_to_phys<T>(virt: *const T) -> u64 {
    (virt as usize as u64).wrapping_sub(PHYSICAL_MAP_BASE)
}

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
                    // Protect first 16MB (where low memory, kernel, and user-mode processes live: 0x000000..0x01000000)
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

// ------------------------------------------------------------------------------------------------
// Dynamic Virtual Memory Manager (VMM) & x86_64 Page Table Operations
// ------------------------------------------------------------------------------------------------

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_PWT: u64 = 1 << 3;
pub const PTE_PCD: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7;
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NX: u64 = 1u64 << 63;

pub static VMM_LOCK: purent_hal::SpinLock<()> = purent_hal::SpinLock::new(());

/// Translate Win32 memory protection flags (PAGE_*) to x86_64 PTE bits
pub fn protect_to_pte_flags(protect: u32, is_user: bool) -> u64 {
    let mut flags = PTE_PRESENT;
    if is_user {
        flags |= PTE_USER;
    }
    match protect & 0xFF {
        purent_ntdef::mem::PAGE_NOACCESS => 0,
        purent_ntdef::mem::PAGE_READONLY => flags | PTE_NX,
        purent_ntdef::mem::PAGE_READWRITE => flags | PTE_WRITABLE | PTE_NX,
        purent_ntdef::mem::PAGE_WRITECOPY => flags | PTE_WRITABLE | PTE_NX,
        purent_ntdef::mem::PAGE_EXECUTE => flags,
        purent_ntdef::mem::PAGE_EXECUTE_READ => flags,
        purent_ntdef::mem::PAGE_EXECUTE_READWRITE | purent_ntdef::mem::PAGE_EXECUTE_WRITECOPY => {
            flags | PTE_WRITABLE
        }
        _ => flags | PTE_WRITABLE,
    }
}

/// Translate x86_64 PTE bits back to Win32 memory protection flags (PAGE_*)
pub fn pte_flags_to_protect(flags: u64) -> u32 {
    if (flags & PTE_PRESENT) == 0 {
        return purent_ntdef::mem::PAGE_NOACCESS;
    }
    let writable = (flags & PTE_WRITABLE) != 0;
    let nx = (flags & PTE_NX) != 0;
    if !nx {
        if writable {
            purent_ntdef::mem::PAGE_EXECUTE_READWRITE
        } else {
            purent_ntdef::mem::PAGE_EXECUTE_READ
        }
    } else {
        if writable {
            purent_ntdef::mem::PAGE_READWRITE
        } else {
            purent_ntdef::mem::PAGE_READONLY
        }
    }
}

/// Map a 4KB virtual page to a physical frame, on-demand splitting 1GB and 2MB huge pages
pub unsafe fn vmm_map_user_page(cr3: u64, va: u64, pa: u64, flags: u64) -> Result<(), NtStatus> {
    if va >= 0x00008000_00000000 {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let _guard = VMM_LOCK.lock();
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4 = phys_to_virt::<u64>(pml4_phys);

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx   = ((va >> 21) & 0x1FF) as usize;
    let pt_idx   = ((va >> 12) & 0x1FF) as usize;

    // 1. PML4 -> PDPT
    let pml4_entry = *pml4.add(pml4_idx);
    let pdpt_phys = if (pml4_entry & PTE_PRESENT) == 0 {
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(new_frame), 0, PAGE_SIZE);
        *pml4.add(pml4_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else {
        pml4_entry & 0x000F_FFFF_FFFF_F000
    };

    // 2. PDPT -> PD
    let pdpt = phys_to_virt::<u64>(pdpt_phys);
    let pdpt_entry = *pdpt.add(pdpt_idx);
    let pd_phys = if (pdpt_entry & PTE_PRESENT) == 0 {
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(new_frame), 0, PAGE_SIZE);
        *pdpt.add(pdpt_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else if (pdpt_entry & PTE_HUGE) != 0 {
        // Split 1GB huge page into 512 x 2MB pages
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        let pd = phys_to_virt::<u64>(new_frame);
        let base_phys = pdpt_entry & 0x000F_FFFF_C000_0000;
        let base_flags = (pdpt_entry & 0xFFF) | (pdpt_entry & PTE_NX);
        for j in 0..512 {
            *pd.add(j) = (base_phys + (j as u64) * 0x200000) | base_flags;
        }
        *pdpt.add(pdpt_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else {
        pdpt_entry & 0x000F_FFFF_FFFF_F000
    };

    // 3. PD -> PT
    let pd = phys_to_virt::<u64>(pd_phys);
    let pd_entry = *pd.add(pd_idx);
    let pt_phys = if (pd_entry & PTE_PRESENT) == 0 {
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(new_frame), 0, PAGE_SIZE);
        *pd.add(pd_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else if (pd_entry & PTE_HUGE) != 0 {
        // Split 2MB huge page into 512 x 4KB pages
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        let pt = phys_to_virt::<u64>(new_frame);
        let base_phys = pd_entry & 0x000F_FFFF_FFE0_0000;
        let base_flags = ((pd_entry & 0xFFF) & !PTE_HUGE) | (pd_entry & PTE_NX);
        for k in 0..512 {
            *pt.add(k) = (base_phys + (k as u64) * 0x1000) | base_flags;
        }
        *pd.add(pd_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else {
        pd_entry & 0x000F_FFFF_FFFF_F000
    };

    // 4. PT -> 4KB Physical Frame
    let pt = phys_to_virt::<u64>(pt_phys);
    *pt.add(pt_idx) = (pa & 0x000F_FFFF_FFFF_F000) | flags;

    core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    Ok(())
}

/// Unmap a 4KB virtual page, returning its physical frame address if it was mapped
pub unsafe fn vmm_unmap_user_page(cr3: u64, va: u64) -> Option<u64> {
    if va >= 0x00008000_00000000 {
        return None;
    }

    let _guard = VMM_LOCK.lock();
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4 = phys_to_virt::<u64>(pml4_phys);

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx   = ((va >> 21) & 0x1FF) as usize;
    let pt_idx   = ((va >> 12) & 0x1FF) as usize;

    let pml4_entry = *pml4.add(pml4_idx);
    if (pml4_entry & PTE_PRESENT) == 0 {
        return None;
    }
    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = phys_to_virt::<u64>(pdpt_phys);
    let pdpt_entry = *pdpt.add(pdpt_idx);
    if (pdpt_entry & PTE_PRESENT) == 0 || (pdpt_entry & PTE_HUGE) != 0 {
        return None;
    }
    let pd_phys = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd = phys_to_virt::<u64>(pd_phys);
    let pd_entry = *pd.add(pd_idx);
    if (pd_entry & PTE_PRESENT) == 0 || (pd_entry & PTE_HUGE) != 0 {
        return None;
    }
    let pt_phys = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt = phys_to_virt::<u64>(pt_phys);
    let pt_entry = *pt.add(pt_idx);
    if (pt_entry & PTE_PRESENT) == 0 {
        return None;
    }
    *pt.add(pt_idx) = 0;
    core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    Some(pt_entry & 0x000F_FFFF_FFFF_F000)
}

/// Modify protection flags for a 4KB virtual page
pub unsafe fn vmm_protect_user_page(cr3: u64, va: u64, new_flags: u64) -> Result<u64, NtStatus> {
    if va >= 0x00008000_00000000 {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let _guard = VMM_LOCK.lock();
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4 = phys_to_virt::<u64>(pml4_phys);

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx   = ((va >> 21) & 0x1FF) as usize;
    let pt_idx   = ((va >> 12) & 0x1FF) as usize;

    let pml4_entry = *pml4.add(pml4_idx);
    if (pml4_entry & PTE_PRESENT) == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = phys_to_virt::<u64>(pdpt_phys);
    let pdpt_entry = *pdpt.add(pdpt_idx);
    if (pdpt_entry & PTE_PRESENT) == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let pd_phys = if (pdpt_entry & PTE_HUGE) != 0 {
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        let pd = phys_to_virt::<u64>(new_frame);
        let base_phys = pdpt_entry & 0x000F_FFFF_C000_0000;
        let base_flags = (pdpt_entry & 0xFFF) | (pdpt_entry & PTE_NX);
        for j in 0..512 {
            *pd.add(j) = (base_phys + (j as u64) * 0x200000) | base_flags;
        }
        *pdpt.add(pdpt_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else {
        pdpt_entry & 0x000F_FFFF_FFFF_F000
    };

    let pd = phys_to_virt::<u64>(pd_phys);
    let pd_entry = *pd.add(pd_idx);
    if (pd_entry & PTE_PRESENT) == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let pt_phys = if (pd_entry & PTE_HUGE) != 0 {
        let new_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        let pt = phys_to_virt::<u64>(new_frame);
        let base_phys = pd_entry & 0x000F_FFFF_FFE0_0000;
        let base_flags = ((pd_entry & 0xFFF) & !PTE_HUGE) | (pd_entry & PTE_NX);
        for k in 0..512 {
            *pt.add(k) = (base_phys + (k as u64) * 0x1000) | base_flags;
        }
        *pd.add(pd_idx) = new_frame | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        new_frame
    } else {
        pd_entry & 0x000F_FFFF_FFFF_F000
    };

    let pt = phys_to_virt::<u64>(pt_phys);
    let old_entry = *pt.add(pt_idx);
    if (old_entry & PTE_PRESENT) == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let pa = old_entry & 0x000F_FFFF_FFFF_F000;
    *pt.add(pt_idx) = pa | new_flags;
    core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    Ok(old_entry)
}

/// Query virtual page attributes
pub unsafe fn vmm_query_user_page(cr3: u64, va: u64) -> Option<(u64, u64)> {
    if va >= 0x00008000_00000000 {
        return None;
    }

    let _guard = VMM_LOCK.lock();
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4 = phys_to_virt::<u64>(pml4_phys);

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx   = ((va >> 21) & 0x1FF) as usize;
    let pt_idx   = ((va >> 12) & 0x1FF) as usize;

    let pml4_entry = *pml4.add(pml4_idx);
    if (pml4_entry & PTE_PRESENT) == 0 {
        return None;
    }
    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = phys_to_virt::<u64>(pdpt_phys);
    let pdpt_entry = *pdpt.add(pdpt_idx);
    if (pdpt_entry & PTE_PRESENT) == 0 {
        return None;
    }
    if (pdpt_entry & PTE_HUGE) != 0 {
        let base = pdpt_entry & 0x000F_FFFF_C000_0000;
        return Some((base + (va & 0x3FFF_FFFF), pdpt_entry & 0xFFF));
    }
    let pd_phys = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd = phys_to_virt::<u64>(pd_phys);
    let pd_entry = *pd.add(pd_idx);
    if (pd_entry & PTE_PRESENT) == 0 {
        return None;
    }
    if (pd_entry & PTE_HUGE) != 0 {
        let base = pd_entry & 0x000F_FFFF_FFE0_0000;
        return Some((base + (va & 0x1F_FFFF), pd_entry & 0xFFF));
    }
    let pt_phys = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt = phys_to_virt::<u64>(pt_phys);
    let pt_entry = *pt.add(pt_idx);
    if (pt_entry & PTE_PRESENT) == 0 {
        return None;
    }
    Some((pt_entry & 0x000F_FFFF_FFFF_F000, pt_entry & !0x000F_FFFF_FFFF_F000))
}

// ------------------------------------------------------------------------------------------------
// Native Virtual Memory System Services (ZwAllocateVirtualMemory, ZwFreeVirtualMemory, etc.)
// ------------------------------------------------------------------------------------------------

pub static USER_VIRTUAL_BUMP: AtomicUsize = AtomicUsize::new(0x00000000_20000000);

#[no_mangle]
pub unsafe extern "win64" fn ZwAllocateVirtualMemory(
    _process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    _zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NtStatus {
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let req_size = *region_size;
    if req_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let aligned_size = (req_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let target_base: u64 = if (*base_address).is_null() {
        let gran_size = (aligned_size + 0xFFFF) & !0xFFFF;
        let bump = USER_VIRTUAL_BUMP.fetch_add(gran_size, Ordering::SeqCst) as u64;
        bump
    } else {
        ((*base_address) as u64) & !(PAGE_SIZE as u64 - 1)
    };

    let num_pages = aligned_size / PAGE_SIZE;
    let cr3 = purent_hal::cpu::read_cr3();
    let pte_flags = protect_to_pte_flags(protect, true);

    kprintln!(
        "[MM] ZwAllocateVirtualMemory: Base=0x{:016X}, Size=0x{:X} ({} pages), Type=0x{:X}, Protect=0x{:X}",
        target_base,
        aligned_size,
        num_pages,
        allocation_type,
        protect
    );

    if (allocation_type & (purent_ntdef::mem::MEM_COMMIT | purent_ntdef::mem::MEM_RESERVE)) != 0 {
        for i in 0..num_pages {
            let page_va = target_base + (i as u64) * (PAGE_SIZE as u64);
            let frame = match PMM.lock().allocate_frame() {
                Some(f) => f,
                None => return STATUS_NO_MEMORY,
            };
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, PAGE_SIZE);

            if let Err(status) = vmm_map_user_page(cr3, page_va, frame, pte_flags) {
                PMM.lock().free_frame(frame);
                return status;
            }
        }
    }

    *base_address = target_base as *mut core::ffi::c_void;
    *region_size = aligned_size;
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwFreeVirtualMemory(
    _process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    free_type: u32,
) -> NtStatus {
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start_va = ((*base_address) as u64) & !(PAGE_SIZE as u64 - 1);
    let req_size = *region_size;
    let aligned_size = (req_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = if aligned_size > 0 { aligned_size / PAGE_SIZE } else { 1 };

    kprintln!(
        "[MM] ZwFreeVirtualMemory: Base=0x{:016X}, Size=0x{:X} ({} pages), FreeType=0x{:X}",
        start_va,
        aligned_size,
        num_pages,
        free_type
    );

    let cr3 = purent_hal::cpu::read_cr3();
    let mut freed_count = 0usize;
    for i in 0..num_pages {
        let page_va = start_va + (i as u64) * (PAGE_SIZE as u64);
        if let Some(frame) = vmm_unmap_user_page(cr3, page_va) {
            PMM.lock().free_frame(frame);
            freed_count += 1;
        }
    }

    kprintln!("[MM] ZwFreeVirtualMemory: successfully reclaimed {} physical frames", freed_count);
    *region_size = 0;
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwQueryVirtualMemory(
    _process_handle: usize,
    base_address: *mut core::ffi::c_void,
    memory_information_class: u32,
    memory_information: *mut core::ffi::c_void,
    memory_information_length: usize,
    return_length: *mut usize,
) -> NtStatus {
    if memory_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if memory_information_class != purent_ntdef::mem::MEMORY_BASIC_INFORMATION {
        return purent_ntdef::status::STATUS_INVALID_INFO_CLASS;
    }
    let mbi_size = core::mem::size_of::<purent_ntdef::mem::MemoryBasicInformation>();
    if memory_information_length < mbi_size {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    let va = base_address as u64;
    let page_va = va & !(PAGE_SIZE as u64 - 1);
    let cr3 = purent_hal::cpu::read_cr3();
    let query_res = vmm_query_user_page(cr3, page_va);

    let mut info: purent_ntdef::mem::MemoryBasicInformation = core::mem::zeroed();
    info.base_address = page_va as *mut core::ffi::c_void;
    info.allocation_base = (page_va & !0xFFFF) as *mut core::ffi::c_void;
    info.region_size = PAGE_SIZE;

    if let Some((_phys, flags)) = query_res {
        info.state = purent_ntdef::mem::MEM_COMMIT;
        info.protect = pte_flags_to_protect(flags);
        info.allocation_protect = info.protect;
        info.r#type = purent_ntdef::mem::MEM_PRIVATE;
    } else {
        info.state = purent_ntdef::mem::MEM_FREE;
        info.protect = purent_ntdef::mem::PAGE_NOACCESS;
        info.allocation_protect = purent_ntdef::mem::PAGE_NOACCESS;
        info.r#type = 0;
    }

    core::ptr::copy_nonoverlapping(
        &info as *const _ as *const u8,
        memory_information as *mut u8,
        mbi_size,
    );
    if !return_length.is_null() {
        *return_length = mbi_size;
    }
    kprintln!(
        "[MM] ZwQueryVirtualMemory: Base=0x{:016X}, State=0x{:X}, Protect=0x{:X}",
        page_va,
        info.state,
        info.protect
    );
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwProtectVirtualMemory(
    _process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NtStatus {
    if base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start_va = ((*base_address) as u64) & !(PAGE_SIZE as u64 - 1);
    let req_size = *region_size;
    let aligned_size = (req_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = if aligned_size > 0 { aligned_size / PAGE_SIZE } else { 1 };

    let cr3 = purent_hal::cpu::read_cr3();
    let new_flags = protect_to_pte_flags(new_protect, true);
    let mut prev_protect = purent_ntdef::mem::PAGE_READWRITE;

    for i in 0..num_pages {
        let page_va = start_va + (i as u64) * (PAGE_SIZE as u64);
        match vmm_protect_user_page(cr3, page_va, new_flags) {
            Ok(old_flags) => {
                if i == 0 {
                    prev_protect = pte_flags_to_protect(old_flags);
                }
            }
            Err(e) => return e,
        }
    }

    if !old_protect.is_null() {
        *old_protect = prev_protect;
    }
    kprintln!(
        "[MM] ZwProtectVirtualMemory: Base=0x{:016X}, Size=0x{:X}, NewProtect=0x{:X}, OldProtect=0x{:X}",
        start_va,
        aligned_size,
        new_protect,
        prev_protect
    );
    STATUS_SUCCESS
}
