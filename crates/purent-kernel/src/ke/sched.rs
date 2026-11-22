//! PureNT Thread Scheduler and Context Switch Engine
//! Implements NT 6.1 x64 (Windows 7 SP1) scheduler mechanics matching ntoskrnl.exe

use core::sync::atomic::{AtomicUsize, Ordering};
use purent_hal::kprintln;
use purent_ntdef::{
    kpcr::{KProcess, KThread, ThreadState},
    status::{NtStatus, STATUS_NO_MEMORY},
};

use crate::ke::arch::{ki_thread_start_trampoline, KiSwapContext};
use crate::mm::{ExAllocatePoolWithTag, NonPagedPool};

pub const THREAD_TAG: u32 = 0x64726854; // 'Thrd'
pub const STACK_TAG: u32 = 0x6B745354;  // 'TStk'
pub const KERNEL_STACK_SIZE: usize = 16 * 1024; // 16 KiB default NT kernel stack
pub const MAX_READY_THREADS: usize = 16;
pub const DEFAULT_QUANTUM: i8 = 2; // 2 clock ticks (20ms @ 100Hz) per thread quantum

pub static CONTEXT_SWITCH_COUNT: AtomicUsize = AtomicUsize::new(0);

pub static mut INITIAL_PROCESS: KProcess = KProcess::empty();

pub static mut BOOT_THREAD: KThread = KThread {
    header: [0; 0x18],
    cycle_time: 0,
    high_cycle_time: 0,
    initial_stack: core::ptr::null_mut(),
    stack_limit: core::ptr::null_mut(),
    kernel_stack: core::ptr::null_mut(),
    thread_lock: 0,
    context_switches_padding: 0,
    state: ThreadState::Running as u8,
    npx_state: 0,
    wait_irql: 0,
    wait_mode: 0,
    padding_1: [0; 0x23],
    process: core::ptr::null_mut(),
    padding_2a: [0; 0x40],
    teb: core::ptr::null_mut(),
    padding_2b: [0; 0x78],
    context_switches: 0,
    priority: 8,
    base_priority: 8,
    quantum: DEFAULT_QUANTUM,
    padding_3a: [0; 0xB7],
    previous_mode: 0,
    padding_3b: [0; 0x169],
};

pub struct SchedulerQueue {
    pub ready_threads: [*mut KThread; MAX_READY_THREADS],
    pub ready_count: usize,
    pub current_index: usize,
}

unsafe impl Send for SchedulerQueue {}

pub static SCHED_QUEUE: purent_hal::SpinLock<SchedulerQueue> = purent_hal::SpinLock::new(SchedulerQueue {
    ready_threads: [core::ptr::null_mut(); MAX_READY_THREADS],
    ready_count: 0,
    current_index: 0,
});

pub unsafe fn sched_init() {
    INITIAL_PROCESS.directory_table_base = purent_hal::cpu::read_cr3();

    BOOT_THREAD.process = &raw mut INITIAL_PROCESS;
    BOOT_THREAD.state = ThreadState::Running as u8;
    BOOT_THREAD.quantum = DEFAULT_QUANTUM;

    {
        let mut q = SCHED_QUEUE.lock();
        q.ready_threads[0] = &raw mut BOOT_THREAD;
        q.ready_count = 1;
        q.current_index = 0;
    }

    kprintln!("[KE] Preemptive Scheduler online (Initial Process PID: 4, Boot Thread: 0x{:016X})", &raw const BOOT_THREAD as usize);
}

pub unsafe fn ps_create_system_thread(
    routine: unsafe extern "win64" fn(*mut core::ffi::c_void),
    context: *mut core::ffi::c_void,
    name: &'static str,
) -> Result<*mut KThread, NtStatus> {
    // 1. Allocate 16 KiB NonPaged pool buffer for the kernel stack
    let stack_buf = ExAllocatePoolWithTag(NonPagedPool, KERNEL_STACK_SIZE, STACK_TAG);
    if stack_buf.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    let stack_top = (stack_buf as usize + KERNEL_STACK_SIZE) & !0xF; // 16-byte aligned

    // 2. Allocate KThread structure
    let thread_size = core::mem::size_of::<KThread>();
    let thread_ptr = ExAllocatePoolWithTag(NonPagedPool, thread_size, THREAD_TAG) as *mut KThread;
    if thread_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    core::ptr::write_bytes(thread_ptr as *mut u8, 0, thread_size);

    (*thread_ptr).initial_stack = stack_top as *mut core::ffi::c_void;
    (*thread_ptr).stack_limit = stack_buf as *mut core::ffi::c_void;
    (*thread_ptr).state = ThreadState::Ready as u8;
    (*thread_ptr).process = &raw mut INITIAL_PROCESS;
    (*thread_ptr).priority = 8;
    (*thread_ptr).base_priority = 8;
    (*thread_ptr).quantum = DEFAULT_QUANTUM;

    // 3. Format initial stack frame for KiSwapContext
    let ret_addr_slot = (stack_top - 8) as *mut usize;
    *ret_addr_slot = ki_thread_start_trampoline as *const () as usize;

    let frame_base = stack_top - 8 - 0x138;
    (*thread_ptr).kernel_stack = frame_base as *mut core::ffi::c_void;

    let rbx_slot = (frame_base + 0x100) as *mut usize;
    *rbx_slot = routine as *const () as usize;

    let rdi_slot = (frame_base + 0x108) as *mut usize;
    *rdi_slot = context as usize;

    // 4. Register thread into ready queue safely
    {
        let mut q = SCHED_QUEUE.lock();
        if q.ready_count >= MAX_READY_THREADS {
            return Err(STATUS_NO_MEMORY);
        }
        let idx = q.ready_count;
        q.ready_threads[idx] = thread_ptr;
        q.ready_count += 1;
    }

    kprintln!(
        "[PS] Created System Thread \"{}\" (KTHREAD: 0x{:016X}, Stack: [0x{:016X}..0x{:016X}], InitialRsp: 0x{:016X})",
        name,
        thread_ptr as usize,
        stack_buf as usize,
        stack_top,
        frame_base
    );

    Ok(thread_ptr)
}

/// Called periodically on APIC timer interrupt
pub unsafe fn ki_quantum_end() {
    let (curr_thread, next_thread) = {
        let mut q = match SCHED_QUEUE.try_lock() {
            Some(g) => g,
            None => return,
        };

        if q.ready_count <= 1 {
            return;
        }

        let curr = q.ready_threads[q.current_index];
        if curr.is_null() {
            return;
        }

        (*curr).quantum -= 1;
        if (*curr).quantum > 0 {
            return;
        }
        (*curr).quantum = DEFAULT_QUANTUM;

        let next_idx = (q.current_index + 1) % q.ready_count;
        let next = q.ready_threads[next_idx];
        if next == curr {
            return;
        }
        q.current_index = next_idx;
        (curr, next)
    };

    let switch_count = CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    kprintln!(
        "[PREEMPT-TIMER] Quantum expired for KTHREAD 0x{:016X} -> Switching to 0x{:016X} (Context Switch #{})",
        curr_thread as usize,
        next_thread as usize,
        switch_count
    );
    KiSwapContext(curr_thread, next_thread);
}

/// Voluntary yield to the next runnable thread
pub unsafe fn ki_yield() {
    let (curr_thread, next_thread) = {
        let mut q = SCHED_QUEUE.lock();
        if q.ready_count <= 1 {
            return;
        }
        let curr = q.ready_threads[q.current_index];
        let next_idx = (q.current_index + 1) % q.ready_count;
        let next = q.ready_threads[next_idx];
        if next == curr {
            return;
        }
        q.current_index = next_idx;
        (curr, next)
    };

    let switch_count = CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    kprintln!(
        "[YIELD-VOLUNTARY] KTHREAD 0x{:016X} yielded CPU -> Switching to 0x{:016X} (Context Switch #{})",
        curr_thread as usize,
        next_thread as usize,
        switch_count
    );
    KiSwapContext(curr_thread, next_thread);
}

/// Wait until a target thread terminates (SignalState != 0 or state == Terminated)
pub unsafe fn ke_wait_for_single_object(thread: *mut KThread) {
    if thread.is_null() {
        return;
    }
    while (*thread).state != ThreadState::Terminated as u8 && (*thread).header[4] == 0 {
        ki_yield();
    }
}
