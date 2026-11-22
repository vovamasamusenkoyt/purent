#![no_std]
#![no_main]

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
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {alloc_type}",
        "mov qword ptr [rsp + 0x30], {protect}",
        "mov r10, {proc}",
        "mov eax, 0x15",
        "syscall",
        "add rsp, 0x40",
        proc = in(reg) process_handle,
        in("rdx") base_address,
        in("r8") zero_bits,
        in("r9") region_size,
        alloc_type = in(reg) allocation_type as u64,
        protect = in(reg) protect as u64,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
unsafe fn nt_free_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    free_type: u32,
) -> i32 {
    let status: i32;
    core::arch::asm!(
        "mov r10, {proc}",
        "mov eax, 0x1B",
        "syscall",
        proc = in(reg) process_handle,
        in("rdx") base_address,
        in("r8") region_size,
        in("r9") free_type as u64,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
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
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {info_len}",
        "mov qword ptr [rsp + 0x30], {ret_len}",
        "mov r10, {proc}",
        "mov eax, 0x20",
        "syscall",
        "add rsp, 0x40",
        proc = in(reg) process_handle,
        in("rdx") base_address,
        in("r8") info_class as u64,
        in("r9") mem_info,
        info_len = in(reg) mem_info_len,
        ret_len = in(reg) return_len,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
unsafe fn nt_protect_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {old_prot}",
        "mov r10, {proc}",
        "mov eax, 0x4D",
        "syscall",
        "add rsp, 0x40",
        proc = in(reg) process_handle,
        in("rdx") base_address,
        in("r8") region_size,
        in("r9") new_protect as u64,
        old_prot = in(reg) old_protect,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[no_mangle]
pub unsafe extern "C" fn main() -> ! {
    // 1. Read TEB address from gs:[0x30] (NtTib.Self)
    let teb_ptr: usize;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb_ptr);

    // 2. Read PEB address from gs:[0x60] (TEB.ProcessEnvironmentBlock)
    let peb_ptr: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

    // 3. Read OSMajorVersion (+0x118) and OSBuildNumber (+0x120) from PEB
    let os_major = *(peb_ptr.wrapping_add(0x118) as *const u32);
    let os_build = *(peb_ptr.wrapping_add(0x120) as *const u16);

    // 4. Read UniqueProcess (PID at +0x40) from TEB
    let _pid = *(teb_ptr.wrapping_add(0x40) as *const usize);

    // 5. Test NtClose syscall (0x0C) with magic handle 0x1337
    core::arch::asm!(
        "mov r10, 0x1337",
        "mov eax, 0x0C", // NtClose
        "syscall",
        out("eax") _,
        out("r10") _,
        out("rcx") _,
        out("r11") _,
    );

    // 6. Test NtYieldExecution syscall (0x43)
    core::arch::asm!(
        "mov eax, 0x43", // NtYieldExecution
        "syscall",
        out("eax") _,
        out("rcx") _,
        out("r11") _,
    );

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

    // 8. Test NtTerminateProcess syscall (0x29) with ExitStatus 0 if PEB and VMM verified
    let exit_status = if os_major == 6 && os_build == 7601 && mem_verified && high_verified {
        0x00000000u32
    } else {
        0xC0000001u32
    };

    core::arch::asm!(
        "mov r10, -1",
        "mov edx, {0:e}",
        "mov eax, 0x29", // NtTerminateProcess
        "syscall",
        in(reg) exit_status,
        out("eax") _,
        out("r10") _,
        out("rdx") _,
        out("rcx") _,
        out("r11") _,
    );

    core::arch::asm!("ud2");

    loop {
        core::hint::spin_loop();
    }
}
