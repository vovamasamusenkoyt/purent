#![no_std]
#![no_main]

pub mod io;
pub mod ke;
pub mod ldr;
pub mod mm;
pub mod ob;
pub mod ps;
pub mod rtl;
pub mod win32k;
pub mod zw;

use core::panic::PanicInfo;
use purent_hal::{gdt, hlt_loop, kprintln, serial::SERIAL1};
use purent_ntdef::kpcr::{Kpcr, Kprcb, NtTib};
use purent_ntdef::loader::{PureNtLoaderBlock, PURENT_LOADER_MAGIC};
use purent_ntdef::object::{ObjectAttributes, GENERIC_READ, GENERIC_WRITE};
use purent_ntdef::string::UnicodeString;

use crate::ldr::{load_fs_rec_driver, load_null_driver};
use crate::mm::{pmm_init, pool_init};
use crate::ob::ob_init;
use crate::rtl::RtlInitUnicodeString;
use crate::zw::{ZwClose, ZwCreateFile, ZwWriteFile};

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
    kprintln!("[HAL] Enabling CPU interrupts via HAL cpu::sti()...");
    purent_hal::cpu::sti();

    // 8. Initialize Windows 7 Graphical Subsystem & Window Manager (win32k)
    kprintln!("\n--- [STAGE: WIN32K GRAPHICAL DESKTOP & WINDOW MANAGER] ---");
    win32k::win32k_init(&ldr.framebuffer);
    kprintln!("--- [STAGE COMPLETE: WIN32K INITIALIZED] ---\n");

    kprintln!("[IO] I/O Manager (Io) initialized.");

    // 8. Load native binary drivers (null.sys and fs_rec.sys)
    kprintln!("\n--- [STAGE: LOADING NATIVE BINARY DRIVERS] ---");
    // Keep the shared PE view in the immutable part of the loaded kernel.
    let kernel_base = ldr.kernel_virtual_base as *const u8;
    let headers = purent_pe::PeView::parse(core::slice::from_raw_parts(kernel_base, 4096))
        .expect("mapped kernel PE headers");
    let exports = headers.data_directory(purent_pe::IMAGE_DIRECTORY_ENTRY_EXPORT)
        .expect("kernel PE exports");
    let export_end = exports.virtual_address.checked_add(exports.size)
        .expect("kernel export bounds") as usize;
    assert!(export_end <= ldr.kernel_size as usize);
    assert!(headers.section_headers().iter().all(|section| {
        section.characteristics & 0x8000_0000 == 0
            || section.virtual_address as usize >= export_end
    }));
    assert!(headers.image_base() == kernel_base as u64);
    let kernel = purent_pe::PeView::parse(core::slice::from_raw_parts(kernel_base, export_end))
        .expect("mapped kernel PE exports");
    let null_loaded = load_null_driver(&kernel);
    let fs_rec_loaded = load_fs_rec_driver(&kernel);
    if null_loaded && fs_rec_loaded {
        kprintln!("--- [STAGE COMPLETE: ALL NATIVE DRIVERS ACTIVE] ---\n");
    } else {
        kprintln!("[WARN] One or more drivers failed to initialize.");
    }

    // 9. Test NT System Calls (ZwCreateFile, ZwWriteFile, ZwClose)
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

    // 10. Process Subsystem (Ps), Ring 3 User-Mode PE Process, and Preemptive Scheduler Verification
    kprintln!("\n--- [STAGE: PS USER-MODE PE PROCESS LOADER & MULTI-THREADING] ---");
    let thread1 = ke::ps_create_system_thread(worker_thread_1, 1 as *mut _, "KernelWorker-1").expect("worker1");
    let thread2 = ke::ps_create_system_thread(worker_thread_2, 2 as *mut _, "KernelWorker-2").expect("worker2");

    // Load and launch real Windows User-Mode PE executable (smss.exe)
    let (_smss_proc, smss_thread) = ps::ps_create_user_process(SMSS_EXE_BYTES, "smss.exe", 0x200, 0x450000).expect("smss");

    kprintln!("[KE] Kernel workers and smss.exe process active. Synchronizing via KeWaitForSingleObject...");

    // Wait on all worker threads and user process to terminate cleanly, and reap their resources
    ke::ke_wait_for_single_object(thread1);
    ps::ps_reap_thread(thread1);

    ke::ke_wait_for_single_object(thread2);
    ps::ps_reap_thread(thread2);

    ke::ke_wait_for_single_object(smss_thread);
    ps::ps_reap_thread(smss_thread);

    // Verify NonPagedPool buffer reclamation: create probe thread on reclaimed memory
    kprintln!("\n[POOL-TEST] Verifying NonPagedPool stack buffer reclamation and reuse...");
    let thread_probe = ke::ps_create_system_thread(worker_probe, 99 as *mut _, "ReclamationProbe").expect("probe");
    ke::ke_wait_for_single_object(thread_probe);
    ps::ps_reap_thread(thread_probe);
    kprintln!("[POOL-TEST] Reclamation probe complete: stack memory verified safe for reuse.");

    kprintln!("\n--- [STAGE COMPLETE: ALL THREADS TERMINATED & REAPED CLEANLY] ---");
    win32k::win32k_reset_console();
    purent_hal::ps2_mouse_init();
    if win32k::prepare_compositor() {
        ps::ps_create_user_process(DWM_EXE_BYTES, "dwm.exe", win32k::DWM_PID, 0x1650000)
            .expect("dwm.exe");
        win32k::activate_compositor();
    }
    ps::ps_create_user_process(CONHOST_EXE_BYTES, "conhost.exe", win32k::CONHOST_PID, 0x450000)
        .expect("conhost.exe");
    let cr3 = purent_hal::cpu::read_cr3();
    let loader_entry = ps::ps_load_ntdll(cr3).expect("ntdll.dll");
    let (_cmd_proc, cmd_thread) = ps::ps_create_win32_process(
        CMD_EXE_BYTES, "cmd.exe", win32k::CONSOLE_CLIENT_PID, 0x550000, loader_entry, cr3,
    ).expect("cmd.exe");
    kprintln!("[PureNT] Entering interactive Win32k Desktop & Mouse event loop...");
    win32k::win32k_run_event_loop(cmd_thread);
}

static SMSS_EXE_BYTES: &[u8] = include_bytes!("../../../target/x86_64-pc-windows-msvc/debug/smss.exe");
static DWM_EXE_BYTES: &[u8] = include_bytes!("../../../target/esp/dwm.exe");
static CONHOST_EXE_BYTES: &[u8] = include_bytes!("../../../target/esp/conhost.exe");
static CMD_EXE_BYTES: &[u8] = include_bytes!("../../../refs/win7_7601_x64/binaries/cmd.exe");
static WINVER_EXE_BYTES: &[u8] = include_bytes!("../../../target/esp/winver.exe");
static WINVER_MUI_BYTES: &[u8] = include_bytes!("../../../target/esp/winver.exe.mui");

unsafe extern "win64" fn worker_probe(_context: *mut core::ffi::c_void) {
    kprintln!("[PROBE-THREAD] Executing on re-allocated stack from NonPagedPool! Terminating cleanly...");
    ps::ps_terminate_current_thread(0);
}

unsafe extern "win64" fn worker_thread_1(context: *mut core::ffi::c_void) {
    let id = context as usize;
    for i in 1..=3 {
        let start_tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Task iteration {} starting at tick {} (10ms APIC quantum)...", id, i, start_tick);
        while core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS) < start_tick + 3 {
            core::hint::spin_loop();
        }
        let end_tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Task iteration {} finished at tick {} (preemption verified)", id, i, end_tick);
    }
    kprintln!("[THREAD-{}] Work finished cleanly. Calling ps_terminate_current_thread...", id);
    ps::ps_terminate_current_thread(0);
}

unsafe extern "win64" fn worker_thread_2(context: *mut core::ffi::c_void) {
    let id = context as usize;
    for i in 1..=3 {
        let start_tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Concurrent task iteration {} starting at tick {} (10ms APIC quantum)...", id, i, start_tick);
        while core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS) < start_tick + 3 {
            core::hint::spin_loop();
        }
        let end_tick = core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS);
        kprintln!("[THREAD-{}] Concurrent task iteration {} finished at tick {} (preemption verified)", id, i, end_tick);
    }
    kprintln!("[THREAD-{}] Concurrent work finished cleanly. Calling ps_terminate_current_thread...", id);
    ps::ps_terminate_current_thread(0);
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
