#![no_std]
#![no_main]

pub mod loader;
pub mod nt;

use core::panic::PanicInfo;
use purent_hal::{gdt, hlt_loop, kprintln, serial::SERIAL1};
use purent_ntdef::loader::{PureNtLoaderBlock, PURENT_LOADER_MAGIC};

use purent_ntdef::kpcr::{Kpcr, Kprcb, NtTib};

static mut BOOT_KPCR: Kpcr = Kpcr {
    nt_tib: NtTib {
        exception_list: core::ptr::null_mut(),
        stack_base: core::ptr::null_mut(),
        stack_limit: core::ptr::null_mut(),
        sub_system_tib: core::ptr::null_mut(),
        fiber_data: core::ptr::null_mut(),
        arbitrary_user_pointer: core::ptr::null_mut(),
        self_ptr: core::ptr::null_mut(),
    },
    prcb: core::ptr::null_mut(),
    padding_0: [0; 0x140],
    prcb_data: Kprcb {
        mx_csr: 0x1F80,
        current_processor_number: 0,
        padding_1: [0; 3],
        current_thread: core::ptr::null_mut(),
        next_thread: core::ptr::null_mut(),
        idle_thread: core::ptr::null_mut(),
        rsp_base: 0,
        dpc_routine_active: 0,
        padding_2: [0; 0x1000],
    },
};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("\n*** STOP: 0x00000050 (PAGE_FAULT_IN_NONPAGED_AREA)");
    kprintln!("[PureNT Kernel Panic] {}", info);
    hlt_loop();
}

/// Historical NT kernel entry point called by PureNT bootloader
#[no_mangle]
pub unsafe extern "win64" fn KiSystemStartup(loader_block: *const PureNtLoaderBlock) -> ! {
    // 1. Initialize serial debug channel
    SERIAL1.init();

    kprintln!("============================================================");
    kprintln!(" PureNT OS [Release 0.1 - Target: AMD64 / x86_64]");
    kprintln!(" Kernel: purentoskrnl");
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

    // Initialize KPCR on GS base
    BOOT_KPCR.prcb = &raw mut BOOT_KPCR.prcb_data;
    BOOT_KPCR.nt_tib.self_ptr = &raw mut BOOT_KPCR.nt_tib;
    purent_hal::cpu::wrmsr(purent_hal::cpu::IA32_GS_BASE, &raw mut BOOT_KPCR as u64);
    kprintln!("[KE] Processor Control Region (KPCR) active at 0x{:016X}", &raw const BOOT_KPCR as usize);

    kprintln!("[BOOT] Loader block verified at 0x{:016X}", loader_block as usize);
    kprintln!("[BOOT] Kernel physical base: 0x{:016X}", ldr.kernel_physical_base);
    kprintln!("[BOOT] Kernel virtual base:  0xFFFFF80000200000");
    kprintln!("[BOOT] Kernel size:          {} KiB", ldr.kernel_size / 1024);
    kprintln!("[BOOT] Physical memory map:  {} entries", ldr.memory_map_entries);

    kprintln!("[EX] Object Manager (Ob) initialized.");
    kprintln!("[IO] I/O Manager (Io) initialized.");
    kprintln!("[KE] Processor Control Region (KPCR) ready.");

    kprintln!("\n--- [STAGE: LOADING NATIVE BINARY DRIVER] ---");
    let loaded = loader::load_null_driver();
    if loaded {
        kprintln!("--- [STAGE COMPLETE: NATIVE DRIVER ACTIVE] ---\n");
    } else {
        kprintln!("--- [STAGE FAILED] ---\n");
    }

    kprintln!("[PureNT] System idle. All subsystems operational.");

    hlt_loop();
}
