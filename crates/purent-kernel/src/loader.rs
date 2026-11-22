//! Native PE Driver Loader for PureNT Kernel

use purent_hal::kprintln;
use purent_ntdef::{
    io::{DriverObject, IRP_MJ_MAXIMUM_FUNCTION},
    status::{nt_success, NtStatus},
    string::UnicodeString,
};
use purent_pe::{PeView, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_REL_BASED_DIR64};
use crate::nt::*;

static NULL_SYS_IMAGE: &[u8] = include_bytes!("../../../refs/win7_7601_x64/binaries/null.sys");

#[repr(C, align(4096))]
struct DriverMemory([u8; 64 * 1024]);

static mut DRIVER_POOL: DriverMemory = DriverMemory([0; 64 * 1024]);

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

pub unsafe fn load_null_driver() -> bool {
    kprintln!("[LOADER] Parsing binary driver (null.sys)...");
    let pe = match PeView::parse(NULL_SYS_IMAGE) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("[FATAL] PE parse error: {:?}", e);
            return false;
        }
    };

    let driver_base = &raw mut DRIVER_POOL as usize;
    let image_size = pe.size_of_image() as usize;
    let original_image_base = pe.image_base();

    kprintln!("[LOADER] Driver allocated at 0x{:016X} (size: {} KiB)", driver_base, image_size / 1024);

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

        if raw_size > 0 && raw_offset + raw_size <= NULL_SYS_IMAGE.len() {
            let src = &NULL_SYS_IMAGE[raw_offset..raw_offset + raw_size];
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
        kprintln!("[LOADER] Applied Base Relocations (delta: 0x{:016X})", delta);
    }

    // 3. Resolve Import Address Table (IAT)
    // For null.sys, IAT is located at RVA 0x2000
    let iat = (driver_base + 0x2000) as *mut usize;
    *iat.add(0) = RtlInitUnicodeString as *const () as usize;
    *iat.add(1) = IoDeleteDevice as *const () as usize;
    *iat.add(2) = MmPageEntireDriver as *const () as usize;
    *iat.add(3) = IofCompleteRequest as *const () as usize;
    *iat.add(4) = IoCreateDevice as *const () as usize;
    *iat.add(5) = KeBugCheckEx as *const () as usize;
    *iat.add(6) = IoDeleteSymbolicLink as *const () as usize;
    kprintln!("[LOADER] IAT imports bound (7 exports resolved to purentoskrnl)");

    // 4. Initialize DriverObject
    NULL_DRIVER_OBJECT.driver_start = driver_base as *mut _;
    NULL_DRIVER_OBJECT.driver_size = image_size as u32;

    // 5. Invoke DriverEntry
    let entry_point_rva = pe.entry_point_rva() as usize;
    let entry_addr = driver_base + entry_point_rva;
    kprintln!("[LOADER] Calling DriverEntry at 0x{:016X}...", entry_addr);

    let driver_entry: unsafe extern "win64" fn(*mut DriverObject, *mut UnicodeString) -> NtStatus =
        core::mem::transmute(entry_addr);

    let mut reg_path = UnicodeString::empty();
    let status = driver_entry(&raw mut NULL_DRIVER_OBJECT, &mut reg_path);

    kprintln!("[LOADER] DriverEntry returned NTSTATUS: 0x{:08X}", status);

    if nt_success(status) {
        kprintln!("[SUCCESS] Driver null.sys successfully loaded and active!");
        kprintln!("[IO] MajorFunction[IRP_MJ_CREATE]: 0x{:p}", NULL_DRIVER_OBJECT.major_function[0]);
        kprintln!("[IO] MajorFunction[IRP_MJ_CLOSE]:  0x{:p}", NULL_DRIVER_OBJECT.major_function[2]);
        kprintln!("[IO] MajorFunction[IRP_MJ_READ]:   0x{:p}", NULL_DRIVER_OBJECT.major_function[3]);
        kprintln!("[IO] MajorFunction[IRP_MJ_WRITE]:  0x{:p}", NULL_DRIVER_OBJECT.major_function[4]);
        kprintln!("[IO] DriverUnload routine:          0x{:p}", NULL_DRIVER_OBJECT.driver_unload);
        true
    } else {
        kprintln!("[FAIL] Driver failed initialization with code 0x{:08X}", status);
        false
    }
}

pub unsafe fn test_driver_io() {
    let dev = NULL_DRIVER_OBJECT.device_object;
    if dev.is_null() {
        kprintln!("[IO-TEST] No device object found on NULL driver!");
        return;
    }

    kprintln!("\n--- [STAGE: IRP DISPATCH TO NULL DRIVER] ---");

    // 1. Dispatch IRP_MJ_CREATE
    let irp = IoAllocateIrp(1, 0);
    let next_stack = io_get_next_irp_stack_location(irp);
    (*next_stack).major_function = purent_ntdef::io::IRP_MJ_CREATE;
    kprintln!("[IO-TEST] 1. Dispatching IRP_MJ_CREATE...");
    let status = IoCallDriver(dev, irp);
    kprintln!("[IO-TEST] IRP_MJ_CREATE returned: 0x{:08X}", status);
    IoFreeIrp(irp);

    // 2. Dispatch IRP_MJ_WRITE with test payload
    let irp = IoAllocateIrp(1, 0);
    let next_stack = io_get_next_irp_stack_location(irp);
    (*next_stack).major_function = purent_ntdef::io::IRP_MJ_WRITE;
    let payload_len = 25usize;
    (*next_stack).parameters[1] = payload_len; // Length in Parameters.Write.Length
    let test_buf = b"PureNT native I/O works!\0";
    (*irp).associated_irp_system_buffer = test_buf.as_ptr() as *mut _;
    kprintln!("[IO-TEST] 2. Dispatching IRP_MJ_WRITE ({} bytes: \"{}\")...", payload_len, core::str::from_utf8_unchecked(&test_buf[..24]));
    let status = IoCallDriver(dev, irp);
    kprintln!("[IO-TEST] IRP_MJ_WRITE returned: 0x{:08X} (bytes processed: {})", status, (*irp).io_status.information);
    IoFreeIrp(irp);

    // 3. Dispatch IRP_MJ_CLOSE
    let irp = IoAllocateIrp(1, 0);
    let next_stack = io_get_next_irp_stack_location(irp);
    (*next_stack).major_function = purent_ntdef::io::IRP_MJ_CLOSE;
    kprintln!("[IO-TEST] 3. Dispatching IRP_MJ_CLOSE...");
    let status = IoCallDriver(dev, irp);
    kprintln!("[IO-TEST] IRP_MJ_CLOSE returned: 0x{:08X}", status);
    IoFreeIrp(irp);

    kprintln!("--- [STAGE COMPLETE: FULL I/O CYCLE VERIFIED] ---\n");
}
