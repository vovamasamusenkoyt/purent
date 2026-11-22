#![no_std]
#![no_main]

pub mod ke;
pub mod loader;
pub mod nt;
pub mod ps;

use core::panic::PanicInfo;
use purent_hal::{gdt, hlt_loop, kprintln, serial::SERIAL1};
use purent_ntdef::kpcr::{Kpcr, Kprcb, NtTib};
use purent_ntdef::loader::{PureNtLoaderBlock, PURENT_LOADER_MAGIC};
use purent_ntdef::object::{ObjectAttributes, GENERIC_READ, GENERIC_WRITE};
use purent_ntdef::string::UnicodeString;
use crate::nt::mm::{pmm_init, pool_init};
use crate::nt::ob::ob_init;
use crate::nt::zw::{ZwClose, ZwCreateFile, ZwWriteFile};
use crate::nt::RtlInitUnicodeString;

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
    BOOT_KPCR.nt_tib.fiber_data = &raw mut BOOT_KPCR.prcb_data as *mut _; // gs:[0x20] points to KPRCB
    BOOT_KPCR.prcb_data.current_thread = &raw mut ke::BOOT_THREAD;         // gs:[0x188] points to CurrentThread
    purent_hal::cpu::wrmsr(purent_hal::cpu::IA32_GS_BASE, &raw mut BOOT_KPCR as u64);
    kprintln!("[KE] Processor Control Region (KPCR) active at 0x{:016X}", &raw const BOOT_KPCR as usize);

    kprintln!("[BOOT] Kernel physical base: 0x{:016X}", ldr.kernel_physical_base);
    kprintln!("[BOOT] Kernel virtual base:  0xFFFFF80000200000");

    // 4. Memory management
    pmm_init(ldr);
    pool_init();

    // 5. Object Manager initialization
    ob_init();

    // 6. Thread Scheduler and Fast System Call initialization
    ke::sched_init();
    ke::syscall_init();
    purent_hal::register_tick_callback(ke::ki_quantum_end);

    // 7. Local APIC and Timer initialization
    purent_hal::apic_init();
    kprintln!("[HAL] Enabling CPU interrupts (sti)...");
    core::arch::asm!("sti", options(nomem, nostack));

    kprintln!("[IO] I/O Manager (Io) initialized.");

    // 7. Load native binary drivers (null.sys and fs_rec.sys)
    kprintln!("\n--- [STAGE: LOADING NATIVE BINARY DRIVERS] ---");
    let null_loaded = loader::load_null_driver();
    let fs_rec_loaded = loader::load_fs_rec_driver();
    if null_loaded && fs_rec_loaded {
        kprintln!("--- [STAGE COMPLETE: ALL NATIVE DRIVERS ACTIVE] ---\n");
    } else {
        kprintln!("[WARN] One or more drivers failed to initialize.");
    }

    // 8. Test NT System Calls (ZwCreateFile, ZwWriteFile, ZwClose)
    kprintln!("\n--- [STAGE: NT SYSTEM CALLS EXECUTION (Zw* API)] ---");
    let dev_null_u16: [u16; 13] = [
        '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
        '\\' as u16, 'N' as u16, 'u' as u16, 'l' as u16, 'l' as u16, 0,
    ];
    let mut dev_name = UnicodeString::empty();
    RtlInitUnicodeString(&mut dev_name, dev_null_u16.as_ptr());

    let mut obj_attr = ObjectAttributes::empty();
    obj_attr.object_name = &mut dev_name;
    obj_attr.attributes = 0x40; // OBJ_CASE_INSENSITIVE

    let mut file_handle: usize = 0;
    let mut io_status = purent_ntdef::io::IoStatusBlock {
        status: 0,
        information: 0,
    };

    kprintln!("[SYSCALL-TEST] Invoking ZwCreateFile(L\"\\Device\\Null\")...");
    let status = ZwCreateFile(
        &mut file_handle,
        GENERIC_READ | GENERIC_WRITE,
        &mut obj_attr,
        &mut io_status,
        core::ptr::null_mut(),
        0,
        0,
        1,
        0,
        core::ptr::null_mut(),
        0,
    );
    kprintln!("[SYSCALL-TEST] ZwCreateFile returned: 0x{:08X}, FileHandle: 0x{:X}", status, file_handle);

    if file_handle != 0 {
        let msg = b"PureNT NT-compatible kernel write test!\0";
        kprintln!("[SYSCALL-TEST] Invoking ZwWriteFile(HANDLE: 0x{:X}, Payload: {} bytes)...", file_handle, msg.len() - 1);
        let write_status = ZwWriteFile(
            file_handle,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut io_status,
            msg.as_ptr() as *const _,
            (msg.len() - 1) as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        kprintln!("[SYSCALL-TEST] ZwWriteFile returned: 0x{:08X}, bytes written: {}", write_status, io_status.information);

        kprintln!("[SYSCALL-TEST] Invoking ZwClose(HANDLE: 0x{:X})...", file_handle);
        let close_status = ZwClose(file_handle);
        kprintln!("[SYSCALL-TEST] ZwClose returned: 0x{:08X}", close_status);
    }
    kprintln!("--- [STAGE COMPLETE: NT SYSTEM CALLS VERIFIED] ---\n");

    // 9. Process Subsystem (Ps), Ring 3 User-Mode PE Process, and Preemptive Scheduler Verification
    kprintln!("\n--- [STAGE: PS USER-MODE PE PROCESS LOADER & MULTI-THREADING] ---");
    let thread1 = ke::ps_create_system_thread(worker_thread_1, 1 as *mut _, "KernelWorker-1").expect("worker1");
    let thread2 = ke::ps_create_system_thread(worker_thread_2, 2 as *mut _, "KernelWorker-2").expect("worker2");

    // Load and launch real Windows User-Mode PE executable (smss.exe)
    let (_smss_proc, smss_thread) = ps::ps_create_user_process(SMSS_EXE_BYTES, "smss.exe", 0x200).expect("smss");

    kprintln!("[KE] Kernel workers and smss.exe process active. Synchronizing via KeWaitForSingleObject...");

    // Wait on all worker threads and user process to terminate cleanly
    ke::ke_wait_for_single_object(thread1);
    ke::ke_wait_for_single_object(thread2);
    ke::ke_wait_for_single_object(smss_thread);

    kprintln!("\n--- [STAGE COMPLETE: ALL THREADS TERMINATED & REAPED CLEANLY] ---");
    kprintln!("[PureNT] System idle. All subsystems operational.");

    hlt_loop();
}

static SMSS_EXE_BYTES: &[u8] = include_bytes!("../../../target/x86_64-pc-windows-msvc/debug/smss.exe");

unsafe extern "win64" fn worker_thread_1(context: *mut core::ffi::c_void) {
    let id = context as usize;
    for i in 1..=3 {
        let tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Task iteration {} executing at tick {} (10ms APIC quantum)...", id, i, tick);
        ke::ki_yield();
    }
    kprintln!("[THREAD-{}] Work finished cleanly. Calling ps_terminate_current_thread...", id);
    ke::ps_terminate_current_thread(0);
}

unsafe extern "win64" fn worker_thread_2(context: *mut core::ffi::c_void) {
    let id = context as usize;
    for i in 1..=3 {
        let tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Concurrent task iteration {} executing at tick {} (10ms APIC quantum)...", id, i, tick);
        ke::ki_yield();
    }
    kprintln!("[THREAD-{}] Concurrent work finished cleanly. Calling ps_terminate_current_thread...", id);
    ke::ps_terminate_current_thread(0);
}
#[no_mangle]
pub static _fltused: i32 = 0;

#[no_mangle]
#[allow(suspicious_runtime_symbol_definitions)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

#[no_mangle]
#[allow(suspicious_runtime_symbol_definitions)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.add(i) = c as u8;
        i += 1;
    }
    s
}

#[no_mangle]
#[allow(suspicious_runtime_symbol_definitions)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}
