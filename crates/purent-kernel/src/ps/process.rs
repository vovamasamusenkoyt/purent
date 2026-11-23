//! PureNT Process and Thread Objects
//! Modeled after Windows NT 6.1 x64 _EPROCESS and _ETHREAD

use purent_ntdef::kpcr::{KProcess, KThread};
use purent_ntdef::ps::{Peb, Teb};

#[repr(C)]
pub struct Process {
    pub pcb: KProcess,                     // +0x000 (DispatcherHeader + DirectoryTableBase at +0x28)
    pub unique_process_id: usize,          // +0x180 (PID in Win7 _EPROCESS)
    pub section_base_address: usize,       // +0x270 (Image Base in Win7 _EPROCESS)
    pub image_file_name: [u8; 16],         // +0x2E0 (Image Name in Win7 _EPROCESS)
    pub peb: *mut Peb,                     // +0x338 (PEB pointer in Win7 _EPROCESS)
    pub exit_status: u32,
}

#[repr(C)]
pub struct Thread {
    pub tcb: KThread,                      // +0x000 (KTHREAD)
    pub unique_thread_id: usize,           // TID
    pub teb: *mut Teb,                     // TEB pointer in user space
    pub process: *mut Process,             // Owner process
    pub user_stack_base: usize,
    pub user_stack_limit: usize,
}

/// Retrieves the scheduler's process ID for the current thread.
pub fn current_process_id() -> Option<usize> {
    unsafe {
        let thread = purent_hal::cpu::read_gs_u64(0x188) as *const KThread;
        let process = thread.as_ref()?.process.cast::<Process>();
        process.as_ref().map(|process| process.unique_process_id)
    }
}
