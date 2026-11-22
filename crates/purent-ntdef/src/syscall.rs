//! Windows NT x64 System Call Abstractions and Trap Frame
//! Reverse-engineered from ntdll.dll and ntoskrnl.exe

use crate::status::NtStatus;

/// PureNT console service. Waits for and returns one ASCII input byte.
pub const SYSCALL_PURENT_CONSOLE_INPUT: u64 = 0x8000;
pub const SYSCALL_PURENT_SHOW_DIALOG: u64 = 0x8001;
pub const SYSCALL_PURENT_CONSOLE_EVENT: u64 = 0x8002;
pub const SYSCALL_PURENT_CONSOLE_SUBMIT: u64 = 0x8003;
pub const SYSCALL_PURENT_CONSOLE_OUTPUT: u64 = 0x8004;
pub const SYSCALL_PURENT_COMPOSE_RECEIVE: u64 = 0x8005;
pub const SYSCALL_PURENT_COMPOSE_FINISH: u64 = 0x8006;
/// Packed console output uses the low 24 bits for bytes and the next byte for length.
pub const CONSOLE_OUTPUT_LENGTH_SHIFT: u32 = 24;
pub const CONSOLE_LINE_CAPACITY: usize = 1024;

/// Hardware and executive trap frame constructed on kernel stack upon `syscall` entry.
/// Matches standard Windows NT x64 `_KTRAP_FRAME` layout for system service dispatch.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TrapFrame {
    // Non-volatile registers (callee-saved)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbx: u64,
    pub rbp: u64,

    // Volatile / syscall parameter registers
    pub r10: u64, // Argument 1 (converted from RCX by user syscall stub)
    pub rdx: u64, // Argument 2
    pub r8:  u64, // Argument 3
    pub r9:  u64, // Argument 4
    pub rax: u64, // Syscall number / return status

    // Hardware trap frame pushed for sysretq / iretq
    pub rip:    u64, // Saved user RIP
    pub cs:     u64, // Saved user CS (0x33)
    pub rflags: u64, // Saved user RFLAGS
    pub rsp:    u64, // Saved user RSP
    pub ss:     u64, // Saved user SS (0x2B)
}

impl TrapFrame {
    /// Read 5th argument passed on user stack (`[user_rsp + 0x28]`)
    #[inline(always)]
    pub unsafe fn arg5<T: Copy>(&self) -> T {
        *(self.rsp.wrapping_add(0x28) as *const T)
    }

    /// Read 6th argument passed on user stack (`[user_rsp + 0x30]`)
    #[inline(always)]
    pub unsafe fn arg6<T: Copy>(&self) -> T {
        *(self.rsp.wrapping_add(0x30) as *const T)
    }

    /// Read 7th argument passed on user stack (`[user_rsp + 0x38]`)
    #[inline(always)]
    pub unsafe fn arg7<T: Copy>(&self) -> T {
        *(self.rsp.wrapping_add(0x38) as *const T)
    }

    /// Read 8th argument passed on user stack (`[user_rsp + 0x40]`)
    #[inline(always)]
    pub unsafe fn arg8<T: Copy>(&self) -> T {
        *(self.rsp.wrapping_add(0x40) as *const T)
    }
}

// ------------------------------------------------------------------------------------------------
// User-Mode System Call Primitives
// Encapsulates all raw inline assembly for Ring 3 applications and client libraries
// ------------------------------------------------------------------------------------------------

#[inline(always)]
pub unsafe fn nt_syscall0(nr: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "mov eax, {nr:e}",
        "syscall",
        nr = in(reg) nr,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall1(nr: u64, a1: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall2(nr: u64, a1: u64, a2: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall5(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {a5}",
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        "add rsp, 0x40",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        a5 = in(reg) a5,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {a5}",
        "mov qword ptr [rsp + 0x30], {a6}",
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        "add rsp, 0x40",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall7(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x40",
        "mov qword ptr [rsp + 0x28], {a5}",
        "mov qword ptr [rsp + 0x30], {a6}",
        "mov qword ptr [rsp + 0x38], {a7}",
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        "add rsp, 0x40",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_syscall10(
    nr: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
    a10: u64,
) -> NtStatus {
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x60",
        "mov qword ptr [rsp + 0x28], {a5}",
        "mov qword ptr [rsp + 0x30], {a6}",
        "mov qword ptr [rsp + 0x38], {a7}",
        "mov qword ptr [rsp + 0x40], {a8}",
        "mov qword ptr [rsp + 0x48], {a9}",
        "mov qword ptr [rsp + 0x50], {a10}",
        "mov r10, {a1}",
        "mov eax, {nr:e}",
        "syscall",
        "add rsp, 0x60",
        nr = in(reg) nr,
        a1 = in(reg) a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        a10 = in(reg) a10,
        lateout("rax") status,
        out("rcx") _,
        out("r11") _,
        out("r10") _,
    );
    status
}

#[inline(always)]
pub unsafe fn nt_current_teb_address() -> usize {
    let teb: usize;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(pure, nomem, nostack));
    teb
}

#[inline(always)]
pub unsafe fn nt_current_peb_address() -> usize {
    let peb: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));
    peb
}
