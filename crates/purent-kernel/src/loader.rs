//! Native PE Driver Loader for PureNT Kernel
//! Loads, relocates, binds, and executes binary NT drivers (.sys) extracted from Windows 7 SP1 x64.

use purent_hal::kprintln;
use purent_ntdef::{
    io::{DriverObject, IRP_MJ_MAXIMUM_FUNCTION},
    status::{nt_success, NtStatus},
    string::UnicodeString,
};
use purent_pe::{PeView, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_REL_BASED_DIR64};
use crate::nt::*;

static NULL_SYS_IMAGE: &[u8] = include_bytes!("../../../refs/win7_7601_x64/binaries/null.sys");
static FS_REC_SYS_IMAGE: &[u8] = include_bytes!("../../../refs/win7_7601_x64/binaries/fs_rec.sys");

#[repr(C, align(4096))]
struct DriverMemory([u8; 64 * 1024]);

static mut NULL_DRIVER_POOL: DriverMemory = DriverMemory([0; 64 * 1024]);
static mut FS_REC_DRIVER_POOL: DriverMemory = DriverMemory([0; 64 * 1024]);

static mut NULL_DRIVER_OBJECT: DriverObject = DriverObject {
    r#type: 4,
    size: core::mem::size_of::<DriverObject>() as u16,
    device_object: core::ptr::null_mut(),
    flags: 0,
    driver_start: core::ptr::null_mut(),
    driver_size: 0,
    driver_section: core::ptr::null_mut(),
    driver_extension: core::ptr::null_mut(),
    driver_name: UnicodeString::empty(),
    hardware_database: core::ptr::null_mut(),
    fast_io_dispatch: core::ptr::null_mut(),
    driver_init: core::ptr::null_mut(),
    driver_start_io: core::ptr::null_mut(),
    driver_unload: core::ptr::null_mut(),
    major_function: [core::ptr::null_mut(); IRP_MJ_MAXIMUM_FUNCTION + 1],
};

static mut FS_REC_DRIVER_OBJECT: DriverObject = DriverObject {
    r#type: 4,
    size: core::mem::size_of::<DriverObject>() as u16,
    device_object: core::ptr::null_mut(),
    flags: 0,
    driver_start: core::ptr::null_mut(),
    driver_size: 0,
    driver_section: core::ptr::null_mut(),
    driver_extension: core::ptr::null_mut(),
    driver_name: UnicodeString::empty(),
    hardware_database: core::ptr::null_mut(),
    fast_io_dispatch: core::ptr::null_mut(),
    driver_init: core::ptr::null_mut(),
    driver_start_io: core::ptr::null_mut(),
    driver_unload: core::ptr::null_mut(),
    major_function: [core::ptr::null_mut(); IRP_MJ_MAXIMUM_FUNCTION + 1],
};

unsafe fn map_pe_driver(image: &[u8], driver_base: usize, driver_name: &str) -> Option<(usize, usize)> {
    kprintln!("[LOADER] Parsing binary driver ({}) ...", driver_name);
    let pe = match PeView::parse(image) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("[FATAL] PE parse error for {}: {:?}", driver_name, e);
            return None;
        }
    };

    let image_size = pe.size_of_image() as usize;
    let original_image_base = pe.image_base();
    kprintln!("[LOADER] Driver {} allocated at 0x{:016X} (size: {} KiB)", driver_name, driver_base, image_size / 1024);

    // 1. Copy section headers into memory
    for sec in pe.section_headers() {
        let name_bytes = &sec.name;
        let mut name_end = 0;
        while name_end < 8 && name_bytes[name_end] != 0 {
            name_end += 1;
        }
        let sec_name = core::str::from_utf8_unchecked(&name_bytes[..name_end]);

        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_addr = sec.virtual_address as usize;

        if raw_size > 0 && raw_offset + raw_size <= image.len() {
            let src = &image[raw_offset..raw_offset + raw_size];
            let dst = (driver_base + virt_addr) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, raw_size);
            kprintln!("[LOADER] Mapped section {:<8} -> 0x{:016X} ({} bytes)", sec_name, driver_base + virt_addr, raw_size);
        }
    }

    // 2. Base relocations
    let delta = (driver_base as i64) - (original_image_base as i64);
    let nt = pe.nt_headers();
    let reloc_dir = nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if reloc_dir.virtual_address != 0 && reloc_dir.size > 0 {
        let mut offset = reloc_dir.virtual_address as usize;
        let end_offset = offset + reloc_dir.size as usize;

        while offset < end_offset {
            let page_va = *(driver_base.wrapping_add(offset) as *const u32) as usize;
            let block_size = *(driver_base.wrapping_add(offset + 4) as *const u32) as usize;
            if block_size == 0 {
                break;
            }

            let entries_count = (block_size - 8) / 2;
            let entries = (driver_base.wrapping_add(offset + 8)) as *const u16;

            for i in 0..entries_count {
                let entry = *entries.add(i);
                let rel_type = entry >> 12;
                let rel_offset = (entry & 0x0FFF) as usize;

                if rel_type == IMAGE_REL_BASED_DIR64 {
                    let patch_target = (driver_base + page_va + rel_offset) as *mut u64;
                    *patch_target = (*patch_target as i64 + delta) as u64;
                }
            }

            offset += block_size;
        }
        kprintln!("[LOADER] Applied Base Relocations for {} (delta: 0x{:016X})", driver_name, delta);
    }

    Some((image_size, pe.entry_point_rva() as usize))
}

pub unsafe fn load_null_driver() -> bool {
    let driver_base = &raw mut NULL_DRIVER_POOL as usize;
    let (image_size, entry_rva) = match map_pe_driver(NULL_SYS_IMAGE, driver_base, "null.sys") {
        Some(v) => v,
        None => return false,
    };

    // Bind IAT (RVA 0x2000, 7 exports)
    let iat = (driver_base + 0x2000) as *mut usize;
    *iat.add(0) = RtlInitUnicodeString as *const () as usize;
    *iat.add(1) = IoDeleteDevice as *const () as usize;
    *iat.add(2) = MmPageEntireDriver as *const () as usize;
    *iat.add(3) = IofCompleteRequest as *const () as usize;
    *iat.add(4) = IoCreateDevice as *const () as usize;
    *iat.add(5) = KeBugCheckEx as *const () as usize;
    *iat.add(6) = IoDeleteSymbolicLink as *const () as usize;
    kprintln!("[LOADER] IAT imports bound for null.sys (7 exports resolved to purentoskrnl)");

    NULL_DRIVER_OBJECT.driver_start = driver_base as *mut _;
    NULL_DRIVER_OBJECT.driver_size = image_size as u32;

    let entry_addr = driver_base + entry_rva;
    kprintln!("[LOADER] Calling DriverEntry at 0x{:016X}...", entry_addr);

    let driver_entry: unsafe extern "win64" fn(*mut DriverObject, *mut UnicodeString) -> NtStatus =
        core::mem::transmute(entry_addr);

    let mut reg_path = UnicodeString::empty();
    let status = driver_entry(&raw mut NULL_DRIVER_OBJECT, &mut reg_path);

    kprintln!("[LOADER] DriverEntry returned NTSTATUS: 0x{:08X}", status);

    if nt_success(status) {
        kprintln!("[SUCCESS] Driver null.sys successfully loaded and active!");
        true
    } else {
        kprintln!("[FAIL] Driver null.sys failed with code 0x{:08X}", status);
        false
    }
}

pub unsafe fn load_fs_rec_driver() -> bool {
    let driver_base = &raw mut FS_REC_DRIVER_POOL as usize;
    let (image_size, entry_rva) = match map_pe_driver(FS_REC_SYS_IMAGE, driver_base, "fs_rec.sys") {
        Some(v) => v,
        None => return false,
    };

    // Bind IAT for fs_rec.sys (RVA 0x2000, 20 exports, confirmed via IDA Pro 9.2)
    let iat = (driver_base + 0x2000) as *mut usize;
    *iat.add(0) = ExAllocatePoolWithTag as *const () as usize;
    *iat.add(1) = IoBuildDeviceIoControlRequest as *const () as usize;
    *iat.add(2) = IoUnregisterFileSystem as *const () as usize;
    *iat.add(3) = ExFreePoolWithTag as *const () as usize;
    *iat.add(4) = KeLeaveCriticalRegion as *const () as usize;
    *iat.add(5) = IoBuildSynchronousFsdRequest as *const () as usize;
    *iat.add(6) = IoRegisterFileSystem as *const () as usize;
    *iat.add(7) = RtlInitUnicodeString as *const () as usize;
    *iat.add(8) = KeSetEvent as *const () as usize;
    *iat.add(9) = KeInitializeEvent as *const () as usize;
    *iat.add(10) = MmPageEntireDriver as *const () as usize;
    *iat.add(11) = KeEnterCriticalRegion as *const () as usize;
    *iat.add(12) = ZwCreateFile as *const () as usize;
    *iat.add(13) = ZwClose as *const () as usize;
    *iat.add(14) = IofCompleteRequest as *const () as usize;
    *iat.add(15) = KeWaitForSingleObject as *const () as usize;
    *iat.add(16) = IoCreateDevice as *const () as usize;
    *iat.add(17) = ZwLoadDriver as *const () as usize;
    *iat.add(18) = IofCallDriver as *const () as usize;
    *iat.add(19) = KeBugCheckEx as *const () as usize;
    kprintln!("[LOADER] IAT imports bound for fs_rec.sys (20 exports resolved to purentoskrnl)");

    FS_REC_DRIVER_OBJECT.driver_start = driver_base as *mut _;
    FS_REC_DRIVER_OBJECT.driver_size = image_size as u32;

    let entry_addr = driver_base + entry_rva;
    kprintln!("[LOADER] Calling DriverEntry for fs_rec.sys at 0x{:016X}...", entry_addr);

    let driver_entry: unsafe extern "win64" fn(*mut DriverObject, *mut UnicodeString) -> NtStatus =
        core::mem::transmute(entry_addr);

    let mut reg_path = UnicodeString::empty();
    let status = driver_entry(&raw mut FS_REC_DRIVER_OBJECT, &mut reg_path);

    kprintln!("[LOADER] fs_rec.sys DriverEntry returned NTSTATUS: 0x{:08X}", status);

    if nt_success(status) {
        kprintln!("[SUCCESS] Driver fs_rec.sys (File System Recognizer) successfully loaded and active!");
        true
    } else {
        kprintln!("[FAIL] Driver fs_rec.sys failed with code 0x{:08X}", status);
        false
    }
}
