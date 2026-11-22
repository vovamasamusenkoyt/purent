//! Windows NT 6.1 x64 (Windows 7 SP1) Process & Thread Subsystem Structures
//! Exact byte offsets reverse-engineered from ntoskrnl.exe and ntdll.dll PDB symbols

use crate::list::ListEntry;
use crate::string::UnicodeString;
use crate::kpcr::NtTib;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ClientId {
    pub unique_process: *mut core::ffi::c_void, // 0x00 (PID)
    pub unique_thread: *mut core::ffi::c_void,  // 0x08 (TID)
}

impl ClientId {
    pub const fn empty() -> Self {
        Self {
            unique_process: core::ptr::null_mut(),
            unique_thread: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PebLdrData {
    pub length: u32,                                          // 0x00
    pub initialized: u8,                                      // 0x04
    pub padding: [u8; 3],                                     // 0x05..0x08
    pub ss_handle: *mut core::ffi::c_void,                    // 0x08
    pub in_load_order_module_list: ListEntry,                 // 0x10
    pub in_memory_order_module_list: ListEntry,               // 0x20
    pub in_initialization_order_module_list: ListEntry,       // 0x30
    pub entry_in_progress: *mut core::ffi::c_void,            // 0x40
    pub shutdown_in_progress: u8,                             // 0x48
    pub padding2: [u8; 7],                                    // 0x49..0x50
    pub shutdown_thread_id: *mut core::ffi::c_void,           // 0x50
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,                                  // 0x00
    pub length: u32,                                          // 0x04
    pub flags: u32,                                           // 0x08
    pub debug_flags: u32,                                     // 0x0C
    pub console_handle: *mut core::ffi::c_void,               // 0x10
    pub console_flags: u32,                                   // 0x18
    pub padding1: u32,                                        // 0x1C
    pub standard_input: *mut core::ffi::c_void,               // 0x20
    pub standard_output: *mut core::ffi::c_void,              // 0x28
    pub standard_error: *mut core::ffi::c_void,               // 0x30
    pub current_directory_path: UnicodeString,                // 0x38 (CURDIR.DosPath)
    pub current_directory_handle: *mut core::ffi::c_void,     // 0x48 (CURDIR.Handle)
    pub dll_path: UnicodeString,                              // 0x50
    pub image_path_name: UnicodeString,                       // 0x60
    pub command_line: UnicodeString,                          // 0x70
    pub environment: *mut core::ffi::c_void,                  // 0x80
}

/// Process Environment Block (PEB) - Windows 7 SP1 x64 (size: 0x380)
#[repr(C, align(8))]
pub struct Peb {
    pub inherited_address_space: u8,                          // 0x000
    pub read_image_file_exec_options: u8,                     // 0x001
    pub being_debugged: u8,                                   // 0x002
    pub bit_field: u8,                                        // 0x003
    pub padding_0: [u8; 4],                                   // 0x004..0x008
    pub mutant: *mut core::ffi::c_void,                       // 0x008
    pub image_base_address: *mut core::ffi::c_void,           // 0x010
    pub ldr: *mut PebLdrData,                                 // 0x018
    pub process_parameters: *mut RtlUserProcessParameters,    // 0x020
    pub sub_system_data: *mut core::ffi::c_void,              // 0x028
    pub process_heap: *mut core::ffi::c_void,                 // 0x030
    pub fast_peb_lock: *mut core::ffi::c_void,                // 0x038
    pub atl_thunk_slist_ptr: *mut core::ffi::c_void,          // 0x040
    pub ifeo_key: *mut core::ffi::c_void,                     // 0x048
    pub cross_process_flags: u32,                             // 0x050
    pub padding_1: u32,                                       // 0x054
    pub user_shared_info_ptr: *mut core::ffi::c_void,         // 0x058
    pub system_reserved: u32,                                 // 0x060
    pub atl_thunk_slist_ptr32: u32,                           // 0x064
    pub api_set_map: *mut core::ffi::c_void,                  // 0x068
    pub tls_expansion_counter: u32,                           // 0x070
    pub padding_2: u32,                                       // 0x074
    pub tls_bitmap: *mut core::ffi::c_void,                   // 0x078
    pub tls_bitmap_bits: [u32; 2],                            // 0x080
    pub read_only_shared_memory_base: *mut core::ffi::c_void, // 0x088
    pub hotpatch_information: *mut core::ffi::c_void,         // 0x090
    pub read_only_static_server_data: *mut *mut core::ffi::c_void, // 0x098
    pub ansi_code_page_data: *mut core::ffi::c_void,          // 0x0A0
    pub oem_code_page_data: *mut core::ffi::c_void,           // 0x0A8
    pub unicode_case_table_data: *mut core::ffi::c_void,      // 0x0B0
    pub number_of_processors: u32,                            // 0x0B8
    pub nt_global_flag: u32,                                  // 0x0BC
    pub critical_section_timeout: i64,                        // 0x0C0
    pub heap_segment_reserve: u64,                            // 0x0C8
    pub heap_segment_commit: u64,                             // 0x0D0
    pub heap_decommit_total_free_threshold: u64,              // 0x0D8
    pub heap_decommit_free_block_threshold: u64,              // 0x0E0
    pub number_of_heaps: u32,                                 // 0x0E8
    pub maximum_number_of_heaps: u32,                         // 0x0EC
    pub process_heaps: *mut *mut core::ffi::c_void,           // 0x0F0
    pub gdi_shared_handle_table: *mut core::ffi::c_void,      // 0x0F8
    pub process_starter_helper: *mut core::ffi::c_void,       // 0x100
    pub gdi_dc_attribute_list: u32,                           // 0x108
    pub padding_3: u32,                                       // 0x10C
    pub loader_lock: *mut core::ffi::c_void,                  // 0x110
    pub os_major_version: u32,                                // 0x118 (6)
    pub os_minor_version: u32,                                // 0x11C (1)
    pub os_build_number: u16,                                 // 0x120 (7601)
    pub os_csd_version: u16,                                  // 0x122 (1)
    pub os_platform_id: u32,                                  // 0x124 (2 = VER_PLATFORM_WIN32_NT)
    pub image_subsystem: u32,                                 // 0x128
    pub image_subsystem_major_version: u32,                   // 0x12C
    pub image_subsystem_minor_version: u32,                   // 0x130
    pub padding_4: u32,                                       // 0x134
    pub active_process_affinity_mask: u64,                    // 0x138
    pub gdi_handle_buffer: [u32; 60],                         // 0x140..0x230
    pub post_process_init_routine: *mut core::ffi::c_void,    // 0x230
    pub tls_expansion_bitmap: *mut core::ffi::c_void,         // 0x238
    pub tls_expansion_bitmap_bits: [u32; 32],                 // 0x240..0x2C0
    pub session_id: u32,                                      // 0x2C0
    pub padding_5: u32,                                       // 0x2C4
    pub app_compat_flags: u64,                                // 0x2C8
    pub app_compat_flags_user: u64,                           // 0x2D0
    pub p_shim_data: *mut core::ffi::c_void,                  // 0x2D8
    pub app_compat_info: *mut core::ffi::c_void,              // 0x2E0
    pub csd_version: UnicodeString,                           // 0x2E8
    pub padding_tail: [u8; 0x88],                             // 0x2F8..0x380
}

/// Thread Environment Block (TEB) - Windows 7 SP1 x64 (size: 0x1818)
#[repr(C, align(8))]
pub struct Teb {
    pub nt_tib: NtTib,                                        // 0x000..0x038
    pub environment_pointer: *mut core::ffi::c_void,          // 0x038
    pub client_id: ClientId,                                  // 0x040..0x050
    pub active_rpc_handle: *mut core::ffi::c_void,            // 0x050
    pub thread_local_storage_pointer: *mut core::ffi::c_void, // 0x058
    pub process_environment_block: *mut Peb,                  // 0x060 (points to PEB!)
    pub last_error_value: u32,                                // 0x068
    pub count_of_owned_critical_sections: u32,                // 0x06C
    pub csr_client_thread: *mut core::ffi::c_void,            // 0x070
    pub win32_thread_info: *mut core::ffi::c_void,            // 0x078
    pub user32_reserved: [u32; 26],                           // 0x080..0x0E8
    pub user_reserved: [u32; 5],                              // 0x0E8..0x0FC
    pub padding_0: u32,                                       // 0x0FC..0x100
    pub wow32_reserved: *mut core::ffi::c_void,               // 0x100
    pub current_locale: u32,                                  // 0x108 (0x0409)
    pub fp_software_status_register: u32,                     // 0x10C
    pub system_reserved1: [*mut core::ffi::c_void; 54],       // 0x110..0x2C0
    pub exception_code: i32,                                  // 0x2C0
    pub padding_1: u32,                                       // 0x2C4
    pub activation_context_stack_pointer: *mut core::ffi::c_void, // 0x2C8
    pub spare_bytes: [u8; 24],                                // 0x2D0..0x2E8
    pub tx_fs_context: u32,                                   // 0x2E8
    pub padding_2: u32,                                       // 0x2EC
    pub gdi_teb_batch: [u8; 0x4E8],                           // 0x2F0..0x7D8
    pub real_client_id: ClientId,                             // 0x7D8..0x7E8
    pub padding_tail: [u8; 0x1818 - 0x7E8],                   // 0x7E8..0x1818
}

unsafe impl Send for Peb {}
unsafe impl Sync for Peb {}
unsafe impl Send for Teb {}
unsafe impl Sync for Teb {}

const _: () = {
    assert!(core::mem::size_of::<Peb>() == 0x380);
    assert!(core::mem::offset_of!(Peb, image_base_address) == 0x10);
    assert!(core::mem::offset_of!(Peb, ldr) == 0x18);
    assert!(core::mem::offset_of!(Peb, process_parameters) == 0x20);
    assert!(core::mem::offset_of!(Peb, process_heap) == 0x30);
    assert!(core::mem::offset_of!(Peb, number_of_processors) == 0x0B8);
    assert!(core::mem::offset_of!(Peb, os_major_version) == 0x118);
    assert!(core::mem::offset_of!(Peb, os_minor_version) == 0x11C);
    assert!(core::mem::offset_of!(Peb, os_build_number) == 0x120);
    assert!(core::mem::offset_of!(Peb, session_id) == 0x2C0);

    assert!(core::mem::size_of::<Teb>() == 0x1818);
    assert!(core::mem::offset_of!(Teb, nt_tib) == 0x000);
    assert!(core::mem::offset_of!(Teb, client_id) == 0x040);
    assert!(core::mem::offset_of!(Teb, process_environment_block) == 0x060);
    assert!(core::mem::offset_of!(Teb, last_error_value) == 0x068);
    assert!(core::mem::offset_of!(Teb, current_locale) == 0x108);
};

