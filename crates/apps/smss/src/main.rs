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

    // 7. Test NtTerminateProcess syscall (0x29) with ExitStatus 0 if PEB verified
    let exit_status = if os_major == 6 && os_build == 7601 { 0x00000000u32 } else { 0xC0000001u32 };
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

    loop {
        core::hint::spin_loop();
    }
}
