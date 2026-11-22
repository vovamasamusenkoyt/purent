#![no_std]
#![no_main]

use purent_ntdef::syscall::{
    nt_current_peb_address, nt_current_teb_address, nt_syscall0, nt_syscall1, nt_syscall2,
    nt_syscall4, nt_syscall5, nt_syscall6, nt_syscall7, nt_syscall10,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub static _fltused: i32 = 0;

#[no_mangle]
pub unsafe extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

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
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = c as u8;
        i += 1;
    }
    dest
}

#[no_mangle]
#[allow(suspicious_runtime_symbol_definitions)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

// Windows NT Virtual Memory Constants
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const MEM_RELEASE: u32 = 0x00008000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// Windows 7 SP1 Syscall Numbers
const SYSCALL_NT_CLOSE: u64 = 0x0C;
const SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x15;
const SYSCALL_NT_FREE_VIRTUAL_MEMORY: u64 = 0x1B;
const SYSCALL_NT_QUERY_VIRTUAL_MEMORY: u64 = 0x20;
const SYSCALL_NT_MAP_VIEW_OF_SECTION: u64 = 0x25;
const SYSCALL_NT_UNMAP_VIEW_OF_SECTION: u64 = 0x27;
const SYSCALL_NT_TERMINATE_PROCESS: u64 = 0x29;
const SYSCALL_NT_YIELD_EXECUTION: u64 = 0x43;
const SYSCALL_NT_CREATE_SECTION: u64 = 0x47;
const SYSCALL_NT_PROTECT_VIRTUAL_MEMORY: u64 = 0x4D;

const SEC_COMMIT: u32 = 0x08000000;
const SECTION_ALL_ACCESS: u32 = 0x000F001F;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct MemoryBasicInformation {
    base_address: *mut core::ffi::c_void,
    allocation_base: *mut core::ffi::c_void,
    allocation_protect: u32,
    __alignment1: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    r#type: u32,
    __alignment2: u32,
}

#[inline(always)]
unsafe fn nt_allocate_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    nt_syscall6(
        SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY,
        process_handle as u64,
        base_address as u64,
        zero_bits as u64,
        region_size as u64,
        allocation_type as u64,
        protect as u64,
    )
}

#[inline(always)]
unsafe fn nt_free_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    free_type: u32,
) -> i32 {
    nt_syscall4(
        SYSCALL_NT_FREE_VIRTUAL_MEMORY,
        process_handle as u64,
        base_address as u64,
        region_size as u64,
        free_type as u64,
    )
}

#[inline(always)]
unsafe fn nt_query_virtual_memory(
    process_handle: usize,
    base_address: *mut core::ffi::c_void,
    info_class: u32,
    mem_info: *mut core::ffi::c_void,
    mem_info_len: usize,
    return_len: *mut usize,
) -> i32 {
    nt_syscall6(
        SYSCALL_NT_QUERY_VIRTUAL_MEMORY,
        process_handle as u64,
        base_address as u64,
        info_class as u64,
        mem_info as u64,
        mem_info_len as u64,
        return_len as u64,
    )
}

#[inline(always)]
unsafe fn nt_protect_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    nt_syscall5(
        SYSCALL_NT_PROTECT_VIRTUAL_MEMORY,
        process_handle as u64,
        base_address as u64,
        region_size as u64,
        new_protect as u64,
        old_protect as u64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn main() -> ! {
    // 1. Read TEB address from gs:[0x30] (NtTib.Self) via typed abstraction
    let teb_ptr = nt_current_teb_address();

    // 2. Read PEB address from gs:[0x60] (TEB.ProcessEnvironmentBlock) via typed abstraction
    let peb_ptr = nt_current_peb_address();

    // 3. Read OSMajorVersion (+0x118) and OSBuildNumber (+0x120) from PEB
    let os_major = *(peb_ptr.wrapping_add(0x118) as *const u32);
    let os_build = *(peb_ptr.wrapping_add(0x120) as *const u16);

    // 4. Read UniqueProcess (PID at +0x40) from TEB
    let _pid = *(teb_ptr.wrapping_add(0x40) as *const usize);

    // 5. Test NtClose syscall (0x0C) with magic handle 0x1337
    let _ = nt_syscall1(SYSCALL_NT_CLOSE, 0x1337);

    // 6. Test NtYieldExecution syscall (0x43)
    let _ = nt_syscall0(SYSCALL_NT_YIELD_EXECUTION);

    // 7. Dynamic Virtual Memory Tests:
    // Test A: Allocate 64 KiB at dynamic base (0 = kernel chosen)
    let mut alloc_base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut alloc_size: usize = 65536;
    let st_alloc = nt_allocate_virtual_memory(
        0,
        &mut alloc_base,
        0,
        &mut alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    let mut mem_verified = st_alloc == 0 && !alloc_base.is_null();
    if mem_verified {
        // Write test pattern into user memory
        let ptr = alloc_base as *mut u8;
        let test_magic = b"PureNT-VMM-DynamicUserMemory-OK!";
        for i in 0..test_magic.len() {
            *ptr.add(i) = test_magic[i];
        }
        for i in 0..test_magic.len() {
            if *ptr.add(i) != test_magic[i] {
                mem_verified = false;
            }
        }

        // Query memory basic information
        let mut mbi: MemoryBasicInformation = core::mem::zeroed();
        let mut ret_len: usize = 0;
        let st_query = nt_query_virtual_memory(
            0,
            alloc_base,
            0,
            &mut mbi as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<MemoryBasicInformation>(),
            &mut ret_len,
        );
        if st_query != 0 || mbi.state != MEM_COMMIT {
            mem_verified = false;
        }

        // Protect memory: change to PAGE_READONLY
        let mut old_prot: u32 = 0;
        let mut prot_size = alloc_size;
        let st_prot = nt_protect_virtual_memory(
            0,
            &mut alloc_base,
            &mut prot_size,
            PAGE_READONLY,
            &mut old_prot,
        );
        if st_prot != 0 || old_prot != PAGE_READWRITE {
            mem_verified = false;
        }

        // Free virtual memory
        let st_free = nt_free_virtual_memory(0, &mut alloc_base, &mut alloc_size, MEM_RELEASE);
        if st_free != 0 {
            mem_verified = false;
        }
    }

    // Test B: Allocate 128 KiB above 1GB boundary at 0x4ad00000 (cmd.exe ImageBase)
    // Verifies 1GB huge page splitting and high user-space memory paging
    let mut high_base: *mut core::ffi::c_void = 0x000000004ad00000usize as *mut core::ffi::c_void;
    let mut high_size: usize = 131072;
    let st_high = nt_allocate_virtual_memory(
        0,
        &mut high_base,
        0,
        &mut high_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    let mut high_verified = st_high == 0 && high_base == 0x000000004ad00000usize as *mut core::ffi::c_void;
    if high_verified {
        let ptr = high_base as *mut u8;
        let test_str = b"PureNT-CmdExe-ImageBase-1GB-Split-OK!";
        for i in 0..test_str.len() {
            *ptr.add(i) = test_str[i];
        }
        for i in 0..test_str.len() {
            if *ptr.add(i) != test_str[i] {
                high_verified = false;
            }
        }
        let _ = nt_free_virtual_memory(0, &mut high_base, &mut high_size, MEM_RELEASE);
    }

    // Test C: Section Object (NtCreateSection & NtMapViewOfSection)
    let mut sec_handle: usize = 0;
    let mut sec_size: i64 = 65536; // 64 KiB
    let st_sec_create = nt_syscall7(
        SYSCALL_NT_CREATE_SECTION,
        &mut sec_handle as *mut _ as u64,
        SECTION_ALL_ACCESS as u64,
        0,
        &mut sec_size as *mut _ as u64,
        PAGE_READWRITE as u64,
        SEC_COMMIT as u64,
        0,
    );

    let mut sec_view_base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut sec_view_size: usize = 0;
    let st_sec_map = nt_syscall10(
        SYSCALL_NT_MAP_VIEW_OF_SECTION,
        sec_handle as u64,
        0,
        &mut sec_view_base as *mut _ as u64,
        0,
        0,
        0,
        &mut sec_view_size as *mut _ as u64,
        1,
        0,
        PAGE_READWRITE as u64,
    );

    let mut sec_verified = st_sec_create == 0 && st_sec_map == 0 && !sec_view_base.is_null();
    if sec_verified {
        let ptr = sec_view_base as *mut u8;
        let sec_magic = b"PureNT-SectionObject-ViewMapped-OK!";
        for i in 0..sec_magic.len() {
            *ptr.add(i) = sec_magic[i];
        }
        for i in 0..sec_magic.len() {
            if *ptr.add(i) != sec_magic[i] {
                sec_verified = false;
            }
        }
        let _ = nt_syscall2(SYSCALL_NT_UNMAP_VIEW_OF_SECTION, 0, sec_view_base as u64);
        let _ = nt_syscall1(SYSCALL_NT_CLOSE, sec_handle as u64);
    }

    // 8. Test NtTerminateProcess syscall (0x29) with ExitStatus 0 if PEB, VMM, and Sections verified
    let exit_status = if os_major == 6 && os_build == 7601 && mem_verified && high_verified && sec_verified {
        0x00000000u32
    } else {
        0xC0000001u32
    };

    let _ = nt_syscall2(SYSCALL_NT_TERMINATE_PROCESS, !0u64, exit_status as u64);

    loop {
        core::hint::spin_loop();
    }
}
