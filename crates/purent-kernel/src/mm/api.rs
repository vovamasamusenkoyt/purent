//! NT Virtual Memory Executive System Services (ZwAllocateVirtualMemory, ZwFreeVirtualMemory, etc.)

use core::sync::atomic::{AtomicUsize, Ordering};
use purent_hal::kprintln;
use purent_ntdef::status::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};

use super::pmm::{PMM, PAGE_SIZE};
use super::vmm::{
    phys_to_virt, protect_to_pte_flags, pte_flags_to_protect, vmm_map_owned_user_page,
    vmm_protect_user_page, vmm_query_user_page, vmm_unmap_owned_user_page,
};

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

            if let Err(status) = vmm_map_owned_user_page(cr3, page_va, frame, pte_flags) {
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
        if let Some(frame) = vmm_unmap_owned_user_page(cr3, page_va) {
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

#[no_mangle]
pub unsafe extern "win64" fn MmPageEntireDriver(address: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    address
}
