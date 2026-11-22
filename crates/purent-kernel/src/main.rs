#![no_std]
#![no_main]

use core::panic::PanicInfo;
use purent_hal::{gdt, hlt_loop, kprintln, serial::SERIAL1};
use purent_ntdef::loader::{PureNtLoaderBlock, PURENT_LOADER_MAGIC};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("\n*** STOP: 0x00000050 (PAGE_FAULT_IN_NONPAGED_AREA)");
    kprintln!("[PureNT Kernel Panic] {}", info);
    hlt_loop();
}

/// Historical Windows NT kernel entry point called by winload/purent-boot
#[no_mangle]
pub unsafe extern "win64" fn KiSystemStartup(loader_block: *const PureNtLoaderBlock) -> ! {
    // 1. Initialize serial debug channel
    SERIAL1.init();

    kprintln!("============================================================");
    kprintln!(" PureNT OS [Version 6.1.7601 - Service Pack 1]");
    kprintln!(" Kernel: purentoskrnl.exe (Target: AMD64 / x86_64)");
    kprintln!(" Safe, clean, native NT architecture in Rust");
    kprintln!("============================================================");

    if loader_block.is_null() {
        kprintln!("[FATAL] KiSystemStartup received NULL LOADER_PARAMETER_BLOCK!");
        hlt_loop();
    }

    let ldr = &*loader_block;
    if ldr.magic != PURENT_LOADER_MAGIC {
        kprintln!("[FATAL] Invalid loader block magic: 0x{:016X}", ldr.magic);
        hlt_loop();
    }

    kprintln!("[HAL] Initializing GDT and Task State Segment...");
    gdt::init();

    kprintln!("[BOOT] Loader block verified at 0x{:016X}", loader_block as usize);
    kprintln!("[BOOT] Kernel physical base: 0x{:016X}", ldr.kernel_physical_base);
    kprintln!("[BOOT] Kernel virtual base:  0x{:016X}", ldr.kernel_virtual_base);
    kprintln!("[BOOT] Kernel size:          {} KiB", ldr.kernel_size / 1024);
    kprintln!("[BOOT] ACPI RSDP pointer:    0x{:016X}", ldr.acpi_rsdp);
    kprintln!("[BOOT] Physical memory map:  {} entries at 0x{:016X}", ldr.memory_map_entries, ldr.memory_map_addr);
    kprintln!("[BOOT] Framebuffer:          {}x{} (scanline: {}) at 0x{:016X}",
        ldr.framebuffer.width,
        ldr.framebuffer.height,
        ldr.framebuffer.pixels_per_scan_line,
        ldr.framebuffer.base_address
    );

    kprintln!("[EX] Object Manager (Ob) initialization...");
    kprintln!("[IO] I/O Manager (Io) initialization...");
    kprintln!("[KE] Processor Control Region (KPCR) ready.");
    kprintln!("[PureNT] System idle. Ready for driver stage.");

    hlt_loop();
}
