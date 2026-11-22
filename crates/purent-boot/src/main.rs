#![no_std]
#![no_main]

use core::panic::PanicInfo;
use purent_ntdef::loader::{FramebufferInfo, PureNtLoaderBlock, PURENT_LOADER_MAGIC};
use purent_pe::PeView;

// Embed the kernel built by xtask (native Windows PE32+ executable)
static KERNEL_PE: &[u8] = include_bytes!("../../../target/esp/purentoskrnl.exe");

static mut LOADER_BLOCK: PureNtLoaderBlock = PureNtLoaderBlock {
    magic: PURENT_LOADER_MAGIC,
    version: 1,
    flags: 0,
    kernel_physical_base: 0x00200000,
    kernel_virtual_base: 0xFFFFF80000200000,
    kernel_size: 2 * 1024 * 1024,
    cr3_pml4: 0,
    acpi_rsdp: 0,
    memory_map_addr: 0,
    memory_map_entries: 0,
    memory_map_desc_size: 0,
    framebuffer: FramebufferInfo {
        base_address: 0,
        size: 0,
        width: 1280,
        height: 800,
        pixels_per_scan_line: 1280,
        pixel_format: 1,
    },
    command_line: [0; 256],
};

#[repr(C)]
pub struct EfiGraphicsOutputModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: [u32; 4],
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
pub struct EfiGraphicsOutputProtocolMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut EfiGraphicsOutputModeInformation,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

#[repr(C)]
pub struct EfiGraphicsOutputProtocol {
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *mut EfiGraphicsOutputProtocolMode,
}

#[repr(C)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x9042a9de,
    data2: 0x23dc,
    data3: 0x11d4,
    data4: [0x9a, 0x37, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
};

#[repr(C)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SimpleTextOutputProtocol {
    pub reset: usize,
    pub output_string: unsafe extern "efiapi" fn(*mut SimpleTextOutputProtocol, *const u16) -> usize,
    pub test_string: usize,
    pub query_mode: usize,
    pub set_mode: usize,
    pub set_attribute: usize,
    pub clear_screen: unsafe extern "efiapi" fn(*mut SimpleTextOutputProtocol) -> usize,
    pub set_cursor_position: usize,
    pub enable_cursor: usize,
    pub mode: usize,
}

#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: *mut core::ffi::c_void,
    pub con_in: usize,
    pub console_out_handle: *mut core::ffi::c_void,
    pub con_out: *mut SimpleTextOutputProtocol,
    pub standard_error_handle: *mut core::ffi::c_void,
    pub std_err: *mut SimpleTextOutputProtocol,
    pub runtime_services: usize,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: usize,
}

#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> usize,
    pub free_pages: unsafe extern "efiapi" fn(u64, usize) -> usize,
    pub get_memory_map: unsafe extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> usize,
    pub allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> usize,
    pub free_pool: unsafe extern "efiapi" fn(*mut u8) -> usize,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: usize,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(*mut core::ffi::c_void, usize) -> usize,
    pub get_next_monotonic_count: usize,
    pub stall: usize,
    pub set_watchdog_timer: usize,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: unsafe extern "efiapi" fn(*const EfiGuid, *mut core::ffi::c_void, *mut *mut core::ffi::c_void) -> usize,
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
    val
}

fn serial_init() {
    unsafe {
        outb(0x3F8 + 1, 0x00);
        outb(0x3F8 + 3, 0x80);
        outb(0x3F8 + 0, 0x01);
        outb(0x3F8 + 1, 0x00);
        outb(0x3F8 + 3, 0x03);
        outb(0x3F8 + 2, 0xC7);
        outb(0x3F8 + 4, 0x0B);
    }
}

pub fn serial_print(s: &str) {
    for b in s.bytes() {
        while unsafe { (inb(0x3F8 + 5) & 0x20) == 0 } {
            core::hint::spin_loop();
        }
        if b == b'\n' {
            unsafe { outb(0x3F8, b'\r'); }
            while unsafe { (inb(0x3F8 + 5) & 0x20) == 0 } {
                core::hint::spin_loop();
            }
        }
        unsafe {
            outb(0x3F8, b);
        }
    }
}

pub fn puts(_con_out: *mut SimpleTextOutputProtocol, text: &str) {
    serial_print(text);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_print("[PureNT Boot Panic]\n");
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "efiapi" fn efi_main(
    image_handle: *mut core::ffi::c_void,
    system_table: *mut EfiSystemTable,
) -> usize {
    serial_init();
    let con_out = unsafe { (*system_table).con_out };
    let bs = unsafe { (*system_table).boot_services };

    puts(con_out, "====================================================\n");
    puts(con_out, " PureNT Bootloader\n");
    puts(con_out, " Staging purentoskrnl into higher-half memory...\n");
    puts(con_out, "====================================================\n");

    // 1. Parse embedded native PE kernel (purentoskrnl.exe)
    let pe = match PeView::parse(KERNEL_PE) {
        Ok(view) => view,
        Err(_) => {
            puts(con_out, "[FATAL] Failed to parse purentoskrnl.exe PE binary!\n");
            return 1;
        }
    };
    let entry_point = pe.image_base() + pe.entry_point_rva() as u64;
    serial_print("[BOOT] Kernel PE (purentoskrnl.exe) parsed. Entry point: 0x");
    print_hex_u64(entry_point);
    serial_print("\n");

    // 2. Allocate 4MB physical pages at 0x00200000 for the kernel
    let mut kernel_phys: u64 = 0x00200000;
    let alloc_status = unsafe {
        ((*bs).allocate_pages)(2, 2, 1024, &mut kernel_phys) // AllocateAddress, EfiLoaderData, 1024 pages (4MB)
    };
    if alloc_status != 0 {
        // Fall back to AllocateAnyPages
        let fallback_status = unsafe {
            ((*bs).allocate_pages)(0, 2, 1024, &mut kernel_phys)
        };
        if fallback_status != 0 {
            puts(con_out, "[FATAL] Failed to allocate physical pages for kernel!\n");
            return 1;
        }
    }
    serial_print("[BOOT] Allocated 4MB physical memory for kernel at: 0x");
    print_hex_u64(kernel_phys);
    serial_print("\n");

    // Clear allocated memory
    unsafe {
        core::ptr::write_bytes(kernel_phys as *mut u8, 0, 4 * 1024 * 1024);
    }

    // Copy PE headers (first SizeOfHeaders bytes)
    let headers_size = pe.nt_headers().optional_header.size_of_headers as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(KERNEL_PE.as_ptr(), kernel_phys as *mut u8, headers_size);
    }

    // Copy PE sections
    for sec in pe.section_headers() {
        let raw_size = sec.size_of_raw_data as usize;
        let raw_offset = sec.pointer_to_raw_data as usize;
        let virt_offset = sec.virtual_address as usize;
        if raw_size > 0 && raw_offset + raw_size <= KERNEL_PE.len() {
            let src = unsafe { KERNEL_PE.as_ptr().add(raw_offset) };
            let dst = (kernel_phys as usize + virt_offset) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, raw_size);
            }
        }
    }
    serial_print("[BOOT] Kernel PE sections mapped into memory.\n");

    // 3. Allocate 4 pages for page tables (PML4, PDPT_low, PDPT_kernel, PD_kernel)
    let mut pt_phys: u64 = 0;
    let pt_status = unsafe {
        ((*bs).allocate_pages)(0, 2, 4, &mut pt_phys) // AllocateAnyPages, EfiLoaderData, 4 pages (16KB)
    };
    if pt_status != 0 {
        puts(con_out, "[FATAL] Failed to allocate page tables!\n");
        return 1;
    }
    unsafe {
        core::ptr::write_bytes(pt_phys as *mut u8, 0, 4 * 4096);
    }

    let pml4 = pt_phys as *mut u64;
    let pdpt_low = (pt_phys + 4096) as *mut u64;
    let pdpt_kernel = (pt_phys + 8192) as *mut u64;
    let pd_kernel = (pt_phys + 12288) as *mut u64;

    unsafe {
        // Lower-half identity mapping: map all 512GB physical memory using 1GB huge pages in PDPT_low
        *pml4.add(0) = (pdpt_low as u64) | 0x07; // PRESENT | WRITABLE | USER
        for i in 0..512 {
            *pdpt_low.add(i) = ((i as u64) * 0x40000000) | 0x87; // PRESENT | WRITABLE | USER | 1GB HUGE PAGE
        }

        // Higher-half kernel mapping (0xFFFFF80000000000..0xFFFFF80040000000 = 1GB)
        *pml4.add(496) = (pdpt_kernel as u64) | 0x03; // PML4 entry 496
        // KUSER_SHARED_DATA mapping (0xFFFFF78000000000)
        *pml4.add(495) = (pdpt_kernel as u64) | 0x03; // PML4 entry 495
        *pdpt_kernel.add(0) = (pd_kernel as u64) | 0x03;
        for i in 0..512 {
            // Map higher half 1GB to physical memory where kernel sits
            *pd_kernel.add(i) = ((i as u64) * 0x200000) | 0x83;
        }
    }
    serial_print("[BOOT] Higher-half PML4 constructed at: 0x");
    print_hex_u64(pt_phys);
    serial_print("\n");

    // 4. Fill LOADER_BLOCK & Query GOP
    let bs_words = bs as *const usize;
    // Connect all controllers first to ensure GOP and PCI devices are bound
    let lhb_fn: unsafe extern "efiapi" fn(u32, *const EfiGuid, *mut core::ffi::c_void, *mut usize, *mut *mut *mut core::ffi::c_void) -> usize =
        unsafe { core::mem::transmute(*bs_words.add(39)) }; // 0x138 / 8 = 39
    let cc_fn: unsafe extern "efiapi" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, *mut core::ffi::c_void, bool) -> usize =
        unsafe { core::mem::transmute(*bs_words.add(33)) }; // 0x108 / 8 = 33

    let mut all_handles_count = 0usize;
    let mut all_handles_buf: *mut *mut core::ffi::c_void = core::ptr::null_mut();
    unsafe {
        let st = lhb_fn(0, core::ptr::null(), core::ptr::null_mut(), &mut all_handles_count, &mut all_handles_buf);
        serial_print("[BOOT] All handles count: ");
        print_hex_u64(all_handles_count as u64);
        serial_print(", status: 0x");
        print_hex_u64(st as u64);
        serial_print("\n");
        if all_handles_count > 0 && !all_handles_buf.is_null() {
            for i in 0..all_handles_count {
                let h = *all_handles_buf.add(i);
                cc_fn(h, core::ptr::null_mut(), core::ptr::null_mut(), true);
            }
        }
    }

    // Find any handle that has GraphicsOutput protocol
    let pph_fn: unsafe extern "efiapi" fn(*mut core::ffi::c_void, *mut *mut *const EfiGuid, *mut usize) -> usize =
        unsafe { core::mem::transmute(*bs_words.add(38)) }; // 0x130 / 8 = 38
    unsafe {
        for i in 0..all_handles_count {
            let h = *all_handles_buf.add(i);
            let mut proto_buf: *mut *const EfiGuid = core::ptr::null_mut();
            let mut proto_count = 0usize;
            if pph_fn(h, &mut proto_buf, &mut proto_count) == 0 && proto_count > 0 && !proto_buf.is_null() {
                for p in 0..proto_count {
                    let guid_ptr = *proto_buf.add(p);
                    if !guid_ptr.is_null() {
                        let d1 = (*guid_ptr).data1;
                        if d1 == 0x9042a9de {
                            serial_print("[BOOT] FOUND GOP on handle: 0x");
                            print_hex_u64(h as u64);
                            serial_print("\n");
                            let hp_fn: unsafe extern "efiapi" fn(*mut core::ffi::c_void, *const EfiGuid, *mut *mut core::ffi::c_void) -> usize =
                                core::mem::transmute(*bs_words.add(19)); // 0x98 / 8 = 19
                            let mut gop_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
                            let hp_status = hp_fn(h, guid_ptr, &mut gop_ptr);
                            if hp_status == 0 && !gop_ptr.is_null() {
                                let gop = gop_ptr as *mut EfiGraphicsOutputProtocol;
                                let mode = (*gop).mode;
                                if !mode.is_null() {
                                    // Query available modes and switch to 1280x720 if supported
                                    let qm_fn: unsafe extern "efiapi" fn(*mut EfiGraphicsOutputProtocol, u32, *mut usize, *mut *mut EfiGraphicsOutputModeInformation) -> usize =
                                        core::mem::transmute((*gop).query_mode);
                                    let sm_fn: unsafe extern "efiapi" fn(*mut EfiGraphicsOutputProtocol, u32) -> usize =
                                        core::mem::transmute((*gop).set_mode);

                                    for m in 0..(*mode).max_mode {
                                        let mut info_size = 0usize;
                                        let mut info_ptr: *mut EfiGraphicsOutputModeInformation = core::ptr::null_mut();
                                        if qm_fn(gop, m, &mut info_size, &mut info_ptr) == 0 && !info_ptr.is_null() {
                                            let mw = (*info_ptr).horizontal_resolution;
                                            let mh = (*info_ptr).vertical_resolution;
                                            if mw == 1280 && mh == 720 {
                                                serial_print("[BOOT] Switching GOP to 1280x720 (Mode ");
                                                print_hex_u64(m as u64);
                                                serial_print(")\n");
                                                sm_fn(gop, m);
                                                break;
                                            }
                                        }
                                    }

                                    let info = (*mode).info;
                                    let fb_base = (*mode).frame_buffer_base;
                                    let fb_size = (*mode).frame_buffer_size;
                                    let (w, h, stride, fmt) = if !info.is_null() {
                                        ((*info).horizontal_resolution, (*info).vertical_resolution, (*info).pixels_per_scan_line, (*info).pixel_format)
                                    } else {
                                        (1024, 768, 1024, 1)
                                    };
                                    serial_print("[BOOT] GOP active: ");
                                    print_hex_u64(w as u64);
                                    serial_print("x");
                                    print_hex_u64(h as u64);
                                    serial_print(", FB Base: 0x");
                                    print_hex_u64(fb_base);
                                    serial_print(", Size: 0x");
                                    print_hex_u64(fb_size as u64);
                                    serial_print("\n");

                                    LOADER_BLOCK.framebuffer.base_address = fb_base;
                                    LOADER_BLOCK.framebuffer.size = fb_size;
                                    LOADER_BLOCK.framebuffer.width = w;
                                    LOADER_BLOCK.framebuffer.height = h;
                                    LOADER_BLOCK.framebuffer.pixels_per_scan_line = stride;
                                    LOADER_BLOCK.framebuffer.pixel_format = fmt;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    unsafe {
        LOADER_BLOCK.kernel_physical_base = kernel_phys;
        LOADER_BLOCK.kernel_virtual_base = 0xFFFFF80000200000;
        LOADER_BLOCK.kernel_size = 4 * 1024 * 1024;
        LOADER_BLOCK.cr3_pml4 = pt_phys;
    }

    // 5. Exit Boot Services
    let mut mem_map_size = 0usize;
    let mut map_key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_version = 0u32;

    unsafe {
        ((*bs).get_memory_map)(&mut mem_map_size, core::ptr::null_mut(), &mut map_key, &mut desc_size, &mut desc_version);
    }
    mem_map_size += 4096; // extra buffer
    let mut mem_buf_ptr: *mut u8 = core::ptr::null_mut();
    unsafe {
        ((*bs).allocate_pool)(2, mem_map_size, &mut mem_buf_ptr);
        ((*bs).get_memory_map)(&mut mem_map_size, mem_buf_ptr, &mut map_key, &mut desc_size, &mut desc_version);
        LOADER_BLOCK.memory_map_addr = mem_buf_ptr as u64;
        LOADER_BLOCK.memory_map_entries = (mem_map_size / desc_size) as u64;
        LOADER_BLOCK.memory_map_desc_size = desc_size as u64;
    }

    serial_print("[BOOT] Exiting UEFI Boot Services...\n");
    let exit_status = unsafe {
        ((*bs).exit_boot_services)(image_handle, map_key)
    };
    if exit_status != 0 {
        // Retry once if map_key shifted
        unsafe {
            ((*bs).get_memory_map)(&mut mem_map_size, mem_buf_ptr, &mut map_key, &mut desc_size, &mut desc_version);
            ((*bs).exit_boot_services)(image_handle, map_key);
        }
    }

    serial_print("[BOOT] Boot Services exited. Loading CR3 and jumping to KiSystemStartup...\n");

    // Disable interrupts before switching page tables and jumping to kernel
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // 6. Switch to PureNT PML4
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pt_phys, options(nostack, preserves_flags));
    }

    // 7. Jump into KiSystemStartup
    let ki_system_startup: unsafe extern "win64" fn(*const PureNtLoaderBlock) -> ! =
        unsafe { core::mem::transmute(entry_point) };

    unsafe {
        ki_system_startup(&raw const LOADER_BLOCK);
    }
}

fn print_hex_u64(val: u64) {
    let hex_chars = b"0123456789ABCDEF";
    let mut buf = [b'0'; 16];
    for i in (0..16).rev() {
        buf[i] = hex_chars[((val >> ((15 - i) * 4)) & 0xF) as usize];
    }
    for b in buf {
        while unsafe { (inb(0x3F8 + 5) & 0x20) == 0 } {
            core::hint::spin_loop();
        }
        unsafe {
            outb(0x3F8, b);
        }
    }
}
