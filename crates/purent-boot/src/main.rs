#![no_std]
#![no_main]

pub mod elf;

use core::panic::PanicInfo;
use purent_ntdef::loader::{FramebufferInfo, PureNtLoaderBlock, PURENT_LOADER_MAGIC};
use crate::elf::{Elf64View, PT_LOAD};

// Embed the kernel built by xtask
static KERNEL_ELF: &[u8] = include_bytes!("../../../target/esp/purentoskrnl.exe");

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

pub fn puts(con_out: *mut SimpleTextOutputProtocol, text: &str) {
    serial_print(text);
    let mut buf = [0u16; 128];
    let mut i = 0;
    for ch in text.chars() {
        if ch == '\n' {
            if i < buf.len() - 2 {
                buf[i] = '\r' as u16;
                i += 1;
            }
        }
        if i < buf.len() - 1 {
            buf[i] = ch as u16;
            i += 1;
        } else {
            buf[i] = 0;
            unsafe {
                ((*con_out).output_string)(con_out, buf.as_ptr());
            }
            i = 0;
        }
    }
    if i > 0 {
        buf[i] = 0;
        unsafe {
            ((*con_out).output_string)(con_out, buf.as_ptr());
        }
    }
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

    // 1. Parse embedded kernel ELF
    let elf = match Elf64View::parse(KERNEL_ELF) {
        Ok(view) => view,
        Err(_) => {
            puts(con_out, "[FATAL] Failed to parse kernel ELF binary!\n");
            return 1;
        }
    };
    let entry_point = elf.entry_point();
    serial_print("[BOOT] Kernel ELF parsed. Entry point: 0x");
    print_hex_u64(entry_point);
    serial_print("\n");

    // 2. Allocate 2MB physical pages at 0x00200000 for the kernel
    let mut kernel_phys: u64 = 0x00200000;
    let alloc_status = unsafe {
        ((*bs).allocate_pages)(2, 2, 512, &mut kernel_phys) // AllocateAddress, EfiLoaderData, 512 pages (2MB)
    };
    if alloc_status != 0 {
        // Fall back to AllocateAnyPages
        let fallback_status = unsafe {
            ((*bs).allocate_pages)(0, 2, 512, &mut kernel_phys)
        };
        if fallback_status != 0 {
            puts(con_out, "[FATAL] Failed to allocate physical pages for kernel!\n");
            return 1;
        }
    }
    serial_print("[BOOT] Allocated 2MB physical memory for kernel at: 0x");
    print_hex_u64(kernel_phys);
    serial_print("\n");

    // Clear allocated memory
    unsafe {
        core::ptr::write_bytes(kernel_phys as *mut u8, 0, 2 * 1024 * 1024);
    }

    // Copy LOAD segments
    for ph in elf.program_headers() {
        if ph.r#type == PT_LOAD {
            let offset_in_kernel = (ph.vaddr - 0xFFFFF80000200000) as usize;
            let src = &KERNEL_ELF[ph.offset as usize..(ph.offset + ph.filesz) as usize];
            let dst = (kernel_phys as usize + offset_in_kernel) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr(), dst, ph.filesz as usize);
            }
        }
    }
    serial_print("[BOOT] Kernel program headers copied.\n");

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
        *pml4.add(0) = (pdpt_low as u64) | 0x03; // PRESENT | WRITABLE
        for i in 0..512 {
            *pdpt_low.add(i) = ((i as u64) * 0x40000000) | 0x83; // PRESENT | WRITABLE | 1GB HUGE PAGE
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

    // 4. Fill LOADER_BLOCK
    unsafe {
        LOADER_BLOCK.kernel_physical_base = kernel_phys;
        LOADER_BLOCK.kernel_virtual_base = 0xFFFFF80000200000;
        LOADER_BLOCK.kernel_size = 2 * 1024 * 1024;
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
