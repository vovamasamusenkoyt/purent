//! Kernel Processor Control Region (KPCR) and Processor Control Block (KPRCB)
//! Matches Windows 7 SP1 x64 (NT 6.1.7601) layout

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NtTib {
    pub exception_list: *mut core::ffi::c_void,   // 0x00
    pub stack_base: *mut core::ffi::c_void,       // 0x08
    pub stack_limit: *mut core::ffi::c_void,      // 0x10
    pub sub_system_tib: *mut core::ffi::c_void,   // 0x18
    pub fiber_data: *mut core::ffi::c_void,       // 0x20
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
    pub current_thread: *mut core::ffi::c_void,   // 0x08 (0x188 in KPCR) - _KTHREAD
    pub next_thread: *mut core::ffi::c_void,      // 0x10 (0x190 in KPCR)
    pub idle_thread: *mut core::ffi::c_void,      // 0x18 (0x198 in KPCR)
    pub rsp_base: u64,                            // 0x28 (0x1A8 in KPCR)
    pub dpc_routine_active: u8,                   // 0x30 (0x1B0 in KPCR)
    pub padding_2: [u8; 0x1000],                  // rest of PRCB
}
