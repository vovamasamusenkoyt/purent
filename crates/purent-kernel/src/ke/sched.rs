//! PureNT Thread Scheduler and Context Switch Engine
//! Implements NT 6.1 x64 (Windows 7 SP1) scheduler mechanics matching ntoskrnl.exe

use purent_hal::kprintln;
use purent_ntdef::{
    kpcr::{KProcess, KThread, ThreadState},
    status::{NtStatus, STATUS_NO_MEMORY},
};
use crate::nt::mm::{ExAllocatePoolWithTag, NonPagedPool};

pub const THREAD_TAG: u32 = 0x64726854; // 'Thrd'
pub const STACK_TAG: u32 = 0x6B745354;  // 'TStk'
pub const KERNEL_STACK_SIZE: usize = 16 * 1024; // 16 KiB default NT kernel stack
pub const MAX_READY_THREADS: usize = 16;
pub const DEFAULT_QUANTUM: i8 = 6; // 6 clock ticks per thread quantum

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

#[unsafe(naked)]
unsafe extern "win64" fn ki_thread_start_trampoline() {
    core::arch::naked_asm!(
        "sti",
        "mov rcx, rdi", // context passed in RDI -> Windows x64 RCX argument 1
        "call rbx",     // routine passed in RBX
        "1: hlt",
        "jmp 1b",
    );
}

/// Exact replica of Windows NT 6.1 x64 KiSwapContext / SwapContext
/// Saves XMM6-XMM15, callee-saved GPRs, swaps RSP between KTHREAD->KernelStack (offset 0x38),
/// updates KPCR.CurrentPrcb.CurrentThread (gs:[0x188]) and TSS RSP0 (PRCB+0x28).
#[unsafe(naked)]
#[allow(non_snake_case)]
pub unsafe extern "win64" fn KiSwapContext(
    current_thread: *mut KThread,
    next_thread: *mut KThread,
) {
    core::arch::naked_asm!(
        // 1. Allocate 0x138 stack frame (matching ntoskrnl KiSwapContext)
        "sub rsp, 0x138",

        // 2. Save non-volatile XMM registers (XMM6 - XMM15)
        "movdqu [rsp + 0x30], xmm6",
        "movdqu [rsp + 0x40], xmm7",
        "movdqu [rsp + 0x50], xmm8",
        "movdqu [rsp + 0x60], xmm9",
        "movdqu [rsp + 0x70], xmm10",
        "movdqu [rsp + 0x80], xmm11",
        "movdqu [rsp + 0xA0], xmm12",
        "movdqu [rsp + 0xB0], xmm13",
        "movdqu [rsp + 0xC0], xmm14",
        "movdqu [rsp + 0xD0], xmm15",

        // 3. Save callee-saved GPRs (RBX, RDI, RSI, R12, R13, R14, R15)
        "mov [rsp + 0x100], rbx",
        "mov [rsp + 0x108], rdi",
        "mov [rsp + 0x110], rsi",
        "mov [rsp + 0x118], r12",
        "mov [rsp + 0x120], r13",
        "mov [rsp + 0x128], r14",
        "mov [rsp + 0x130], r15",

        // 4. Set up registers for SwapContext:
        // RDI = CurrentThread, RSI = NextThread, RBX = KPCR.CurrentPrcb (gs:[0x20])
        "mov rdi, rcx",
        "mov rsi, rdx",
        "mov rbx, gs:[0x20]",

        // 5. Swap Stacks:
        // Save current RSP into CurrentThread->KernelStack (offset 0x38)
        "mov [rdi + 0x38], rsp",
        // Load new RSP from NextThread->KernelStack (offset 0x38)
        "mov rsp, [rsi + 0x38]",

        // 6. Update Prcb.CurrentThread (gs:[0x188]) to NextThread
        "mov gs:[0x188], rsi",

        // 7. Update Prcb.RspBase (TSS RSP0 target at PRCB + 0x28) to NextThread->InitialStack
        "mov rax, [rsi + 0x28]",
        "test rbx, rbx",
        "jz 1f",
        "mov [rbx + 0x28], rax",
        "1:",
        "push rsi",
        "push rdi",
        "mov rcx, rax",
        "call {set_rsp0}",
        "pop rdi",
        "pop rsi",

        // 8. Update thread states: CurrentThread = Ready (1), NextThread = Running (2)
        "mov byte ptr [rdi + 0x49], 1",
        "mov byte ptr [rsi + 0x49], 2",
        "inc dword ptr [rsi + 0x138]",

        // 9. Check if CR3 needs reloading (NextThread->Process vs CurrentThread->Process)
        "mov rax, [rsi + 0x70]",
        "cmp rax, [rdi + 0x70]",
        "je 2f",
        "test rax, rax",
        "jz 2f",
        "mov rdx, [rax + 0x28]",
        "mov cr3, rdx",
        "2:",

        // 10. Update IA32_KERNEL_GS_BASE if NextThread has a TEB (offset 0xB8)
        "mov r8, [rsi + 0x0B8]",
        "test r8, r8",
        "jz 3f",
        "mov ecx, 0xC0000102",
        "mov eax, r8d",
        "shr r8, 32",
        "mov edx, r8d",
        "wrmsr",
        "3:",

        // 11. Restore GPRs from new thread's stack
        "mov rbx, [rsp + 0x100]",
        "mov rdi, [rsp + 0x108]",
        "mov rsi, [rsp + 0x110]",
        "mov r12, [rsp + 0x118]",
        "mov r13, [rsp + 0x120]",
        "mov r14, [rsp + 0x128]",
        "mov r15, [rsp + 0x130]",

        // 11. Restore XMM registers
        "movdqu xmm6, [rsp + 0x30]",
        "movdqu xmm7, [rsp + 0x40]",
        "movdqu xmm8, [rsp + 0x50]",
        "movdqu xmm9, [rsp + 0x60]",
        "movdqu xmm10, [rsp + 0x70]",
        "movdqu xmm11, [rsp + 0x80]",
        "movdqu xmm12, [rsp + 0xA0]",
        "movdqu xmm13, [rsp + 0xB0]",
        "movdqu xmm14, [rsp + 0xC0]",
        "movdqu xmm15, [rsp + 0xD0]",

        // 12. Deallocate stack frame and return to thread's instruction stream!
        "add rsp, 0x138",
        "ret",
        set_rsp0 = sym purent_hal::gdt::set_rsp0,
    );
}

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
        "[PS] Created System Thread \"{}\" (KTHREAD: 0x{:016X}, KernelStack: 0x{:016X})",
        name,
        thread_ptr as usize,
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

/// Terminate the currently running thread:
/// - Mark state = Terminated
/// - Set DispatcherHeader SignalState = 1
/// - Remove from SCHED_QUEUE ready threads
/// - Switch immediately to next ready thread via KiSwapContext
pub unsafe fn ps_terminate_current_thread(exit_status: u32) -> ! {
    let curr = {
        let q = SCHED_QUEUE.lock();
        q.ready_threads[q.current_index]
    };

    kprintln!("[PS] Thread 0x{:016X} terminating (ExitStatus: 0x{:08X}). Removing from Ready Queue...", curr as usize, exit_status);

    let next = {
        let mut q = SCHED_QUEUE.lock();
        (*curr).state = ThreadState::Terminated as u8;
        (*curr).header[4] = 1; // SignalState = 1 in DispatcherHeader (offset 0x04)

        // Remove curr from ready_threads list
        let mut found_idx = None;
        for i in 0..q.ready_count {
            if q.ready_threads[i] == curr {
                found_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = found_idx {
            for j in idx..(q.ready_count - 1) {
                q.ready_threads[j] = q.ready_threads[j + 1];
            }
            let last_idx = q.ready_count - 1;
            q.ready_threads[last_idx] = core::ptr::null_mut();
            q.ready_count = last_idx;
        }

        if q.current_index >= q.ready_count {
            q.current_index = 0;
        }

        q.ready_threads[q.current_index]
    };

    kprintln!("[KE] Switching context away from terminated thread to 0x{:016X}...", next as usize);
    KiSwapContext(curr, next);

    // Will never be scheduled again
    loop {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

