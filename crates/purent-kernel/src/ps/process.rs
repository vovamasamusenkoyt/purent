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
