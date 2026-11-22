//! Windows NT 6.1 (Build 7601 SP1 x64) Fast System Call Engine (`syscall` / `sysretq`)
//! Reverse-engineered from ntoskrnl.exe (`KiSystemCall64`) and ntdll.dll

use purent_hal::cpu::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
use purent_hal::kprintln;

use crate::ke::arch::ki_system_call_64;

// Windows 7 SP1 x64 System Call Numbers from ntdll.dll
pub const SYSCALL_NT_READ_FILE: u64 = 0x03;
pub const SYSCALL_NT_DEVICE_IO_CONTROL_FILE: u64 = 0x04;
pub const SYSCALL_NT_WRITE_FILE: u64 = 0x05;
pub const SYSCALL_NT_CLOSE: u64 = 0x0C;
pub const SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x15;
pub const SYSCALL_NT_FREE_VIRTUAL_MEMORY: u64 = 0x1B;
pub const SYSCALL_NT_QUERY_VIRTUAL_MEMORY: u64 = 0x20;
pub const SYSCALL_NT_MAP_VIEW_OF_SECTION: u64 = 0x25;
pub const SYSCALL_NT_UNMAP_VIEW_OF_SECTION: u64 = 0x27;
pub const SYSCALL_NT_TERMINATE_PROCESS: u64 = 0x29;
pub const SYSCALL_NT_OPEN_FILE: u64 = 0x30;
pub const SYSCALL_NT_DELAY_EXECUTION: u64 = 0x31;
pub const SYSCALL_NT_YIELD_EXECUTION: u64 = 0x43;
pub const SYSCALL_NT_CREATE_SECTION: u64 = 0x47;
pub const SYSCALL_NT_PROTECT_VIRTUAL_MEMORY: u64 = 0x4D;
pub const SYSCALL_NT_TERMINATE_THREAD: u64 = 0x50;
pub const SYSCALL_NT_CREATE_FILE: u64 = 0x52;

/// Initialize x86_64 Model Specific Registers for low-latency SYSCALL/SYSRET
pub unsafe fn syscall_init() {
    // 1. Enable SCE (System Call Extensions) and NXE (No-Execute Enable) in IA32_EFER
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | 1 | (1 << 11));

    // 2. IA32_STAR:
    // Bits 32..47: SYSCALL CS/SS base = 0x10 (Kernel CS = 0x10, Kernel DS = 0x18)
    // Bits 48..63: SYSRET CS/SS base  = 0x23 (User DS = 0x2B, User CS = 0x33)
    let star_val: u64 = ((0x0023u64) << 48) | ((0x0010u64) << 32);
    wrmsr(IA32_STAR, star_val);

    // 3. IA32_LSTAR: Linear address of KiSystemCall64 entry
    wrmsr(IA32_LSTAR, ki_system_call_64 as *const () as usize as u64);

    // 4. IA32_FMASK: Mask RFLAGS bits on syscall entry (clears IF, TF, DF, NT, RF)
    wrmsr(IA32_FMASK, 0x257FD5);

    kprintln!("[KE] Low latency system call (syscall/sysretq) configured via LSTAR 0x{:016X}", ki_system_call_64 as *const () as usize);
}
