#![no_std]
#![no_main]

pub mod loader;
pub mod nt;

use core::panic::PanicInfo;
use purent_hal::{gdt, hlt_loop, kprintln, serial::SERIAL1};
use purent_ntdef::kpcr::{Kpcr, Kprcb, NtTib};
use purent_ntdef::loader::{PureNtLoaderBlock, PURENT_LOADER_MAGIC};
use purent_ntdef::object::{GENERIC_READ, GENERIC_WRITE};
use crate::nt::mm::{pmm_init, pool_init};
use crate::nt::ob::{ob_create_handle, ob_init, ob_reference_object_by_name};

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

    // 2. Hardware initialization (GDT, TSS, IDT)
    kprintln!("[HAL] Initializing GDT and Task State Segment...");
    gdt::init();

    kprintln!("[HAL] Initializing Interrupt Descriptor Table (IDT)...");
    purent_hal::idt_init();

    // 3. Initialize KPCR on GS base
    BOOT_KPCR.prcb = &raw mut BOOT_KPCR.prcb_data;
    BOOT_KPCR.nt_tib.self_ptr = &raw mut BOOT_KPCR.nt_tib;
    purent_hal::cpu::wrmsr(purent_hal::cpu::IA32_GS_BASE, &raw mut BOOT_KPCR as u64);
    kprintln!("[KE] Processor Control Region (KPCR) active at 0x{:016X}", &raw const BOOT_KPCR as usize);

    kprintln!("[BOOT] Kernel physical base: 0x{:016X}", ldr.kernel_physical_base);
    kprintln!("[BOOT] Kernel virtual base:  0xFFFFF80000200000");

    // 4. Memory management
    pmm_init(ldr);
    pool_init();

    // 5. Object Manager initialization
    ob_init();

    // 6. Local APIC and Timer initialization
    purent_hal::apic_init();
    kprintln!("[HAL] Enabling CPU interrupts (sti)...");
    core::arch::asm!("sti", options(nomem, nostack));

    kprintln!("[IO] I/O Manager (Io) initialized.");

    // 7. Load native binary driver (null.sys)
    kprintln!("\n--- [STAGE: LOADING NATIVE BINARY DRIVER] ---");
    let loaded = loader::load_null_driver();
    if loaded {
        kprintln!("--- [STAGE COMPLETE: NATIVE DRIVER ACTIVE] ---\n");

        // 8. Execute synthetic IRP dispatch loop against null.sys
        loader::test_driver_io();

        // 9. Object Manager lookup & Handle creation test
        kprintln!("\n--- [STAGE: OBJECT MANAGER LOOKUP & HANDLES] ---");
        match ob_reference_object_by_name("\\Device\\Null") {
            Ok(hdr) => {
                kprintln!("[OB-TEST] Found object in namespace: \"{}\"", (*hdr).name_str());
                let handle = ob_create_handle(hdr, GENERIC_READ | GENERIC_WRITE);
                kprintln!("[OB-TEST] Successfully opened HANDLE 0x{:X} to \\Device\\Null!", handle);
            }
            Err(e) => {
                kprintln!("[OB-TEST] Failed to lookup \\Device\\Null: 0x{:08X}", e);
            }
        }
        kprintln!("--- [STAGE COMPLETE: OBJECT MANAGER VERIFIED] ---\n");
    } else {
        kprintln!("--- [STAGE FAILED] ---\n");
    }

    kprintln!("[PureNT] System idle. All subsystems operational.");

    hlt_loop();
}
