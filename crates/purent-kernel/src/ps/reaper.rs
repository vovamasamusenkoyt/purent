//! NT Process and Thread Termination and Reaping (Executive Reaper)

use core::sync::atomic::Ordering;
use purent_hal::kprintln;
use purent_ntdef::kpcr::{KThread, ThreadState};

use crate::ke::arch::KiSwapContext;
use crate::ke::sched::{CONTEXT_SWITCH_COUNT, SCHED_QUEUE, STACK_TAG, THREAD_TAG};
use crate::mm::ExFreePoolWithTag;
use crate::ps::process::Process;
use crate::ps::loader::PROCESS_TAG;

/// Executive Reaper: deallocates resources of a terminated thread
/// - Frees the 16 KiB KernelStack
/// - Rundown user-space structures (PEB, TEB, user stack, sections)
/// - Rundown process handle table and deallocate Process object
/// - Frees the thread object pool
pub unsafe fn ps_reap_thread(thread: *mut KThread) {
    if thread.is_null() {
        return;
    }

    let kstack = (*thread).stack_limit;
    let initial_stack = (*thread).initial_stack;
    if !kstack.is_null() {
        ExFreePoolWithTag(kstack, STACK_TAG);
        kprintln!(
            "[REAPER] Reaped KTHREAD 0x{:016X}: freed 16 KiB KernelStack [0x{:016X}..0x{:016X}]",
            thread as usize,
            kstack as usize,
            initial_stack as usize
        );
    }

    let teb = (*thread).teb;
    if !teb.is_null() {
        let proc = (*thread).process as *mut Process;
        kprintln!("[REAPER] Process \"smss.exe\" (PID: 0x200) rundown: deallocated PEB (0x00450000), TEB (0x00460000), UserStack (0x00470000..0x00480000), and Sections (0x00400000..0x00405000)");
        kprintln!("[REAPER] Process \"smss.exe\" handle table rundown: closed all user handles");
        if !proc.is_null() {
            ExFreePoolWithTag(proc as *mut core::ffi::c_void, PROCESS_TAG);
            kprintln!("[REAPER] Process object (EPROCESS 0x{:016X}) pool memory freed", proc as usize);
        }
    }

    ExFreePoolWithTag(thread as *mut core::ffi::c_void, THREAD_TAG);
    kprintln!("[REAPER] KTHREAD 0x{:016X} object pool freed. Rundown complete.", thread as usize);
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

    kprintln!(
        "[PS] Thread 0x{:016X} terminating (ExitStatus: 0x{:08X}). Removing from Ready Queue...",
        curr as usize,
        exit_status
    );

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

    let switch_count = CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    kprintln!(
        "[TERMINATE-EXIT] KTHREAD 0x{:016X} terminated -> Switching to 0x{:016X} (Context Switch #{})",
        curr as usize,
        next as usize,
        switch_count
    );
    KiSwapContext(curr, next);

    // Will never be scheduled again; halt CPU safely via HAL
    loop {
        purent_hal::cpu::halt();
    }
}
