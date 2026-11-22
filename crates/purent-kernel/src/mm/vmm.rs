//! Virtual Memory Manager (VMM) and x86_64 Long Mode Paging
//! Implements 4KB on-demand page table walking, huge page splitting (1GB/2MB), and page protection translation.

use purent_ntdef::status::{
    NtStatus, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_UNSUCCESSFUL,
};
use super::pmm::{PMM, PAGE_SIZE};

pub const PHYSICAL_MAP_BASE: u64 = 0xFFFFF80000000000;

#[inline(always)]
pub unsafe fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYSICAL_MAP_BASE + phys) as *mut T
}

#[inline(always)]
pub unsafe fn virt_to_phys<T>(virt: *const T) -> u64 {
    (virt as usize as u64).wrapping_sub(PHYSICAL_MAP_BASE)
}

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

    purent_hal::cpu::invlpg(va);
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
    purent_hal::cpu::invlpg(va);
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
    purent_hal::cpu::invlpg(va);
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
