//! Kernel Processor Control Region (KPCR) and Processor Control Block (KPRCB)
//! Matches Windows 7 SP1 x64 (NT 6.1.7601) layout

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
    DeferredReady = 7,
}

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
pub struct KProcess {
    pub header: [u8; 0x18],                     // 0x00..0x18 (DispatcherHeader)
    pub profile_list_head: [usize; 2],          // 0x18..0x28
    pub directory_table_base: u64,              // 0x28 (CR3 Page Directory Base)
    pub padding: [u8; 0x100],                   // rest of process struct
}

impl KProcess {
    pub const fn empty() -> Self {
        Self {
            header: [0; 0x18],
            profile_list_head: [0; 2],
            directory_table_base: 0,
            padding: [0; 0x100],
        }
    }
}

#[repr(C, align(16))]
pub struct KThread {
    pub header: [u8; 0x18],                     // 0x00..0x18 (DispatcherHeader)
    pub cycle_time: u64,                        // 0x18
    pub high_cycle_time: u64,                   // 0x20
    pub initial_stack: *mut core::ffi::c_void,  // 0x28 (Base of kernel stack / TSS.RSP0)
    pub stack_limit: *mut core::ffi::c_void,    // 0x30
    pub kernel_stack: *mut core::ffi::c_void,   // 0x38 (Saved RSP during context switch!)
    pub thread_lock: usize,                     // 0x40
    pub context_switches_padding: u8,           // 0x48
    pub state: u8,                              // 0x49 (ThreadState)
    pub npx_state: u8,                          // 0x4A
    pub wait_irql: u8,                          // 0x4B
    pub wait_mode: i8,                          // 0x4C
    pub padding_1: [u8; 0x23],                  // 0x4D..0x70
    pub process: *mut KProcess,                 // 0x70 (Owner Process)
    pub padding_2a: [u8; 0x40],                 // 0x78..0x0B8
    pub teb: *mut core::ffi::c_void,            // 0x0B8 (TEB pointer, matching Win7 x64!)
    pub padding_2b: [u8; 0x78],                 // 0x0C0..0x138
    pub context_switches: u32,                  // 0x138
    pub priority: i8,                           // 0x13C
    pub base_priority: i8,                      // 0x13D
    pub quantum: i8,                            // 0x13E
    pub padding_3a: [u8; 0xB7],                 // 0x13F..0x1F6
    pub previous_mode: i8,                      // 0x1F6 (0 = KernelMode, 1 = UserMode)
    pub padding_3b: [u8; 0x169],                // 0x1F7..0x360
}

unsafe impl Send for KThread {}
unsafe impl Sync for KThread {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NtTib {
    pub exception_list: *mut core::ffi::c_void,   // 0x00
    pub stack_base: *mut core::ffi::c_void,       // 0x08
    pub stack_limit: *mut core::ffi::c_void,      // 0x10
    pub sub_system_tib: *mut core::ffi::c_void,   // 0x18
    pub fiber_data: *mut core::ffi::c_void,       // 0x20 (in KPCR: CurrentPrcb pointer)
    pub arbitrary_user_pointer: *mut core::ffi::c_void, // 0x28
    pub self_ptr: *mut NtTib,                     // 0x30
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Kpcr {
    pub nt_tib: NtTib,                            // 0x00..0x38
    pub prcb: *mut Kprcb,                         // 0x38 (points to prcb_data)
    pub padding_0: [u8; 0x140],                   // 0x40..0x180
    pub prcb_data: Kprcb,                         // 0x180
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Kprcb {
    pub mx_csr: u32,                              // 0x00 (0x180 in KPCR)
    pub current_processor_number: u8,             // 0x04 (0x184 in KPCR)
    pub padding_1: [u8; 3],                       // 0x05..0x08
    pub current_thread: *mut KThread,             // 0x08 (0x188 in KPCR) - _KTHREAD
    pub next_thread: *mut KThread,                // 0x10 (0x190 in KPCR)
    pub idle_thread: *mut KThread,                // 0x18 (0x198 in KPCR)
    pub rsp_base: u64,                            // 0x28 (0x1A8 in KPCR)
    pub dpc_routine_active: u8,                   // 0x30 (0x1B0 in KPCR)
    pub padding_2: [u8; 0x1000],                  // rest of PRCB
}

const _: () = {
    assert!(core::mem::offset_of!(KThread, initial_stack) == 0x28);
    assert!(core::mem::offset_of!(KThread, kernel_stack) == 0x38);
    assert!(core::mem::offset_of!(KThread, process) == 0x70);
    assert!(core::mem::offset_of!(KThread, teb) == 0x0B8);
    assert!(core::mem::offset_of!(KThread, context_switches) == 0x138);
    assert!(core::mem::offset_of!(KThread, previous_mode) == 0x1F6);
    assert!(core::mem::size_of::<KThread>() == 0x360);
};

