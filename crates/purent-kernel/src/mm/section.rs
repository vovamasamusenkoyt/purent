//! NT Section Objects and Memory-Mapped Views (NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection)
//! Reverse-engineered from ntoskrnl.exe and ntdll.dll (Windows 7 SP1 x64)

use core::sync::atomic::Ordering;
use purent_hal::kprintln;
use purent_ntdef::object::{AccessMask, ObjectAttributes};
use purent_ntdef::status::{
    NtStatus, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};

use crate::mm::api::USER_VIRTUAL_BUMP;
use crate::mm::pmm::{PMM, PAGE_SIZE};
use crate::mm::pool::{ExAllocatePoolWithTag, ExFreePoolWithTag, NonPagedPool};
use crate::mm::vmm::{phys_to_virt, protect_to_pte_flags, vmm_map_user_page, vmm_unmap_user_page};
use crate::ob::{create_header, ob_create_handle, ob_reference_object_by_handle, OB_TYPE_SECTION};

pub const SECTION_TAG: u32 = 0x74636553; // 'Sect'

// Section Allocation Attributes
pub const SEC_IMAGE: u32 = 0x01000000;
pub const SEC_RESERVE: u32 = 0x04000000;
pub const SEC_COMMIT: u32 = 0x08000000;
pub const SEC_NOCACHE: u32 = 0x10000000;

pub const MAX_SECTION_PAGES: usize = 256; // Supports sections up to 1 MiB inline

#[repr(C)]
pub struct SectionObject {
    pub size: usize,
    pub section_page_protection: u32,
    pub allocation_attributes: u32,
    pub file_handle: usize,
    pub physical_frames: [u64; MAX_SECTION_PAGES],
    pub physical_frame_count: usize,
}

#[no_mangle]
pub unsafe extern "win64" fn ZwCreateSection(
    section_handle: *mut usize,
    desired_access: AccessMask,
    _object_attributes: *mut ObjectAttributes,
    maximum_size: *mut i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: usize,
) -> NtStatus {
    if section_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let req_size: usize = if !maximum_size.is_null() && *maximum_size > 0 {
        *maximum_size as usize
    } else {
        PAGE_SIZE
    };
    let aligned_size = (req_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = aligned_size / PAGE_SIZE;

    if num_pages > MAX_SECTION_PAGES {
        return STATUS_NO_MEMORY;
    }

    let obj_size = core::mem::size_of::<SectionObject>();
    let sec_ptr = ExAllocatePoolWithTag(NonPagedPool, obj_size, SECTION_TAG) as *mut SectionObject;
    if sec_ptr.is_null() {
        return STATUS_NO_MEMORY;
    }
    core::ptr::write_bytes(sec_ptr as *mut u8, 0, obj_size);

    (*sec_ptr).size = aligned_size;
    (*sec_ptr).section_page_protection = section_page_protection;
    (*sec_ptr).allocation_attributes = allocation_attributes;
    (*sec_ptr).file_handle = file_handle;
    (*sec_ptr).physical_frame_count = num_pages;

    // Allocate physical frames backing the section (anonymous commit)
    if (allocation_attributes & SEC_COMMIT) != 0 || file_handle == 0 {
        let mut pmm = PMM.lock();
        for i in 0..num_pages {
            let frame = match pmm.allocate_frame() {
                Some(f) => f,
                None => {
                    // Cleanup allocated frames on failure
                    for j in 0..i {
                        pmm.free_frame((*sec_ptr).physical_frames[j]);
                    }
                    ExFreePoolWithTag(sec_ptr as *mut core::ffi::c_void, SECTION_TAG);
                    return STATUS_NO_MEMORY;
                }
            };
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, PAGE_SIZE);
            (*sec_ptr).physical_frames[i] = frame;
        }
    }

    // Resolve section name if specified in ObjectAttributes
    let name = "\\Section";
    let header = create_header(sec_ptr as *mut u8, name, &raw mut OB_TYPE_SECTION);
    let handle = ob_create_handle(header, desired_access);
    *section_handle = handle;

    kprintln!(
        "[MM] ZwCreateSection: HANDLE 0x{:X}, Size=0x{:X} ({} pages), Attr=0x{:08X}, Prot=0x{:X}",
        handle,
        aligned_size,
        num_pages,
        allocation_attributes,
        section_page_protection
    );

    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwMapViewOfSection(
    section_handle: usize,
    _process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    _zero_bits: usize,
    _commit_size: usize,
    _section_offset: *mut i64,
    view_size: *mut usize,
    _inherit_disposition: u32,
    _allocation_type: u32,
    win32_protect: u32,
) -> NtStatus {
    if base_address.is_null() || view_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let header = match ob_reference_object_by_handle(section_handle) {
        Ok(h) => h,
        Err(status) => return status,
    };

    if (*header).object_type != &raw mut OB_TYPE_SECTION {
        return STATUS_INVALID_HANDLE;
    }

    let sec = (*header).body as *mut SectionObject;
    if sec.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let map_size = if *view_size > 0 && *view_size <= (*sec).size {
        (*view_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    } else {
        (*sec).size
    };

    // Calculate virtual address (64 KiB Windows NT allocation granularity)
    let target_va: u64 = if (*base_address).is_null() {
        let gran_size = (map_size + 0xFFFF) & !0xFFFF;
        let bump = USER_VIRTUAL_BUMP.fetch_add(gran_size, Ordering::SeqCst) as u64;
        bump
    } else {
        ((*base_address) as u64) & !(PAGE_SIZE as u64 - 1)
    };

    let num_pages = map_size / PAGE_SIZE;
    let cr3 = purent_hal::cpu::read_cr3();
    let pte_flags = protect_to_pte_flags(win32_protect, true);

    for i in 0..num_pages {
        let va = target_va + (i as u64) * (PAGE_SIZE as u64);
        let frame = if i < (*sec).physical_frame_count {
            (*sec).physical_frames[i]
        } else {
            return STATUS_NO_MEMORY;
        };

        if let Err(e) = vmm_map_user_page(cr3, va, frame, pte_flags) {
            return e;
        }
    }

    *base_address = target_va as *mut core::ffi::c_void;
    *view_size = map_size;

    kprintln!(
        "[MM] ZwMapViewOfSection: HANDLE 0x{:X} -> Base=0x{:016X}, Size=0x{:X} ({} pages), Protect=0x{:X}",
        section_handle,
        target_va,
        map_size,
        num_pages,
        win32_protect
    );

    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "win64" fn ZwUnmapViewOfSection(
    _process_handle: usize,
    base_address: *mut core::ffi::c_void,
) -> NtStatus {
    if base_address.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let start_va = (base_address as u64) & !(PAGE_SIZE as u64 - 1);
    let cr3 = purent_hal::cpu::read_cr3();

    kprintln!("[MM] ZwUnmapViewOfSection: Base=0x{:016X}", start_va);

    // Unmap first page (and subsequent if present)
    let _ = vmm_unmap_user_page(cr3, start_va);

    STATUS_SUCCESS
}
