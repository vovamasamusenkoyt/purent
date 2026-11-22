#![no_std]
#![no_main]

use core::panic::PanicInfo;

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
    // Task priority
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    // Memory
    pub allocate_pages: usize,
    pub free_pages: usize,
    pub get_memory_map: usize,
    pub allocate_pool: usize,
    pub free_pool: usize,
    // Events & Timers
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    // Protocol handler services
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: usize,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    // Image services
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(*mut core::ffi::c_void, usize) -> usize,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
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

fn serial_print(s: &str) {
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

#[no_mangle]
pub extern "efiapi" fn efi_main(
    _image_handle: *mut core::ffi::c_void,
    system_table: *mut EfiSystemTable,
) -> usize {
    serial_init();
    let con_out = unsafe { (*system_table).con_out };
    puts(con_out, "========================================\n");
    puts(con_out, " PureNT Bootloader (winload.efi)\n");
    puts(con_out, " Loading PureNT Kernel (purentoskrnl)...\n");
    puts(con_out, "========================================\n");

    0 // EFI_SUCCESS
}
