//! Windows NT 6.1 (Build 7601 SP1 x64) Fast System Call Engine (`syscall` / `sysretq`)
//! Reverse-engineered from ntoskrnl.exe (`KiSystemCall64`) and ntdll.dll

use purent_hal::cpu::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_KERNEL_GS_BASE, IA32_LSTAR, IA32_STAR};
use purent_hal::kprintln;
use purent_ntdef::status::{NtStatus, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use purent_ntdef::{IoStatusBlock, ObjectAttributes};

// Windows 7 SP1 x64 System Call Numbers from ntdll.dll
pub const SYSCALL_NT_READ_FILE: u64 = 0x03;
pub const SYSCALL_NT_DEVICE_IO_CONTROL_FILE: u64 = 0x04;
pub const SYSCALL_NT_WRITE_FILE: u64 = 0x05;
pub const SYSCALL_NT_CLOSE: u64 = 0x0C;
pub const SYSCALL_NT_TERMINATE_PROCESS: u64 = 0x29;
pub const SYSCALL_NT_OPEN_FILE: u64 = 0x30;
pub const SYSCALL_NT_DELAY_EXECUTION: u64 = 0x31;
pub const SYSCALL_NT_YIELD_EXECUTION: u64 = 0x43;
pub const SYSCALL_NT_TERMINATE_THREAD: u64 = 0x50;
pub const SYSCALL_NT_CREATE_FILE: u64 = 0x52;

/// Initialize x86_64 Model Specific Registers for low-latency SYSCALL/SYSRET
pub unsafe fn syscall_init() {
    // 1. Enable SCE (System Call Extensions) in IA32_EFER
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | 1);

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

/// Hardware entry point for Ring 3 `syscall` instruction.
/// Matches Windows NT `KiSystemCall64` ABI.
#[unsafe(naked)]
pub unsafe extern "C" fn ki_system_call_64() {
    core::arch::naked_asm!(
        // 1. Swap user GS base with Kernel KPCR
        "swapgs",

        // 2. Save user RSP in KPCR scratch slot (gs:[0x10] = nt_tib.stack_limit)
        "mov gs:[0x10], rsp",

        // 3. Switch RSP to Kernel Stack from KPCR PRCB RspBase (gs:[0x1A8])
        "mov rsp, gs:[0x1A8]",

        // 4. Construct trap frame on kernel stack (matches iretq layout)
        "push 0x2B",                // User SS (0x28 | 3)
        "push qword ptr gs:[0x10]", // User RSP
        "push r11",                 // User RFLAGS (saved by CPU syscall in r11)
        "push 0x33",                // User CS (0x30 | 3)
        "push rcx",                 // User RIP (saved by CPU syscall in rcx)

        // 5. Save callee-saved and frame registers
        "push rbp",
        "push rbx",
        "push rsi",
        "push rdi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // 6. Enable CPU interrupts during syscall handling (matches Windows NT KiSystemCall64 at 0x14007F723)
        "sti",

        // 7. Windows Syscall calling convention -> Win64 ABI call:
        // EAX = Syscall Number -> RCX (arg 1)
        // R10 = Arg 1          -> RDX (arg 2)
        // RDX = Arg 2          -> R8  (arg 3)
        // R8  = Arg 3          -> R9  (arg 4)
        // R9  = Arg 4          -> [rsp + 0x20] (arg 5)
        // User RSP             -> [rsp + 0x28] (arg 6)
        "sub rsp, 0x38",                // Shadow space (32 bytes) + 2 stack args + 16-byte alignment
        "mov [rsp + 0x20], r9",         // arg 5: a4
        "mov r11, qword ptr gs:[0x10]",
        "mov [rsp + 0x28], r11",        // arg 6: user_rsp
        "mov r9, r8",                   // arg 4: a3
        "mov r8, rdx",                  // arg 3: a2
        "mov rdx, r10",                 // arg 2: a1
        "mov rcx, rax",                 // arg 1: syscall_nr
        "call {dispatch}",
        "add rsp, 0x38",

        // Disable interrupts for atomic user frame restoration (matches Windows NT KiSystemCall64 at 0x14007F91E)
        "cli",

        // 8. Restore registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rdi",
        "pop rsi",
        "pop rbx",
        "pop rbp",

        // 8. Restore user trap frame
        "pop rcx",                  // User RIP for sysretq
        "add rsp, 8",               // Skip User CS
        "pop r11",                  // User RFLAGS for sysretq
        "pop rdx",                  // User RSP
        "add rsp, 8",               // Skip User SS
        "mov rsp, rdx",             // Switch back to User RSP

        // 9. Swap GS back to user space
        "swapgs",

        // 10. Fast return to Ring 3 (sysretq: REX.W 0x0F 0x07)
        ".byte 0x48, 0x0F, 0x07",

        dispatch = sym ki_system_call_dispatch,
    );
}

/// Central dispatch routine for Windows NT system calls originating from Ring 3
#[no_mangle]
pub extern "win64" fn ki_system_call_dispatch(
    syscall_nr: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    user_rsp: u64,
) -> NtStatus {
    match syscall_nr {
        SYSCALL_NT_CREATE_FILE => {
            unsafe {
                let file_handle = a1 as *mut usize;
                let desired_access = a2 as u32;
                let obj_attr = a3 as *mut ObjectAttributes;
                let io_status = a4 as *mut IoStatusBlock;

                let alloc_size = *(user_rsp.wrapping_add(0x28) as *const u64) as *mut i64;
                let file_attr = *(user_rsp.wrapping_add(0x30) as *const u32);
                let share_access = *(user_rsp.wrapping_add(0x38) as *const u32);
                let create_disp = *(user_rsp.wrapping_add(0x40) as *const u32);
                let create_opts = *(user_rsp.wrapping_add(0x48) as *const u32);
                let ea_buf = *(user_rsp.wrapping_add(0x50) as *const u64) as *mut core::ffi::c_void;
                let ea_len = *(user_rsp.wrapping_add(0x58) as *const u32);

                crate::nt::ZwCreateFile(
                    file_handle,
                    desired_access,
                    obj_attr,
                    io_status,
                    alloc_size,
                    file_attr,
                    share_access,
                    create_disp,
                    create_opts,
                    ea_buf,
                    ea_len,
                )
            }
        }

        SYSCALL_NT_WRITE_FILE => {
            unsafe {
                let file_handle = a1 as usize;
                let event = a2 as usize;
                let apc_routine = a3 as *mut core::ffi::c_void;
                let apc_context = a4 as *mut core::ffi::c_void;

                let io_status = *(user_rsp.wrapping_add(0x28) as *const u64) as *mut IoStatusBlock;
                let buffer = *(user_rsp.wrapping_add(0x30) as *const u64) as *mut core::ffi::c_void;
                let length = *(user_rsp.wrapping_add(0x38) as *const u32);
                let byte_offset = *(user_rsp.wrapping_add(0x40) as *const u64) as *mut i64;
                let key = *(user_rsp.wrapping_add(0x48) as *const u64) as *mut u32;

                crate::nt::ZwWriteFile(
                    file_handle,
                    event,
                    apc_routine,
                    apc_context,
                    io_status,
                    buffer,
                    length,
                    byte_offset,
                    key,
                )
            }
        }

        SYSCALL_NT_READ_FILE => {
            unsafe {
                let file_handle = a1 as usize;
                let event = a2 as usize;
                let apc_routine = a3 as *mut core::ffi::c_void;
                let apc_context = a4 as *mut core::ffi::c_void;

                let io_status = *(user_rsp.wrapping_add(0x28) as *const u64) as *mut IoStatusBlock;
                let buffer = *(user_rsp.wrapping_add(0x30) as *const u64) as *mut core::ffi::c_void;
                let length = *(user_rsp.wrapping_add(0x38) as *const u32);
                let byte_offset = *(user_rsp.wrapping_add(0x40) as *const u64) as *mut i64;
                let key = *(user_rsp.wrapping_add(0x48) as *const u64) as *mut u32;

                crate::nt::ZwReadFile(
                    file_handle,
                    event,
                    apc_routine,
                    apc_context,
                    io_status,
                    buffer,
                    length,
                    byte_offset,
                    key,
                )
            }
        }

        SYSCALL_NT_CLOSE => {
            let handle = a1 as usize;
            kprintln!("[SYSCALL] NtClose(Handle=0x{:X})", handle);
            unsafe { crate::nt::ZwClose(handle) }
        }

        SYSCALL_NT_YIELD_EXECUTION => {
            kprintln!("[SYSCALL] NtYieldExecution called from Ring 3 - yielding CPU quantum...");
            unsafe { crate::ke::ki_yield(); }
            kprintln!("[SYSCALL] NtYieldExecution: thread resumed, returning to Ring 3 via sysretq");
            STATUS_SUCCESS
        }

        SYSCALL_NT_TERMINATE_PROCESS => {
            kprintln!("[SYSCALL] NtTerminateProcess(Handle=0x{:X}, ExitStatus=0x{:08X}) - Process exiting!", a1, a2);
            STATUS_SUCCESS
        }

        _ => {
            kprintln!("[SYSCALL] Unknown Nt/Zw service 0x{:04X} (a1=0x{:X}, a2=0x{:X})", syscall_nr, a1, a2);
            STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Transition from Ring 0 (Kernel) to Ring 3 (User-Mode) via `iretq`
/// Sets up user stack, user code selector (0x33), user data selector (0x2B), and drops CPL to 3.
pub unsafe fn enter_user_mode(entry_point: u64, user_stack: u64) -> ! {
    kprintln!("[KE] Entering User-Mode (Ring 3) at RIP=0x{:016X}, RSP=0x{:016X}...", entry_point, user_stack);

    // Swap GS base: put KPCR into IA32_KERNEL_GS_BASE so the first Ring 3 syscall can swapgs it back!
    let kpcr_ptr = purent_hal::cpu::rdmsr(purent_hal::cpu::IA32_GS_BASE);
    wrmsr(IA32_KERNEL_GS_BASE, kpcr_ptr);
    wrmsr(purent_hal::cpu::IA32_GS_BASE, 0); // Clear user GS base

    // Execute iretq with:
    // [rsp + 0x00] = RIP
    // [rsp + 0x08] = CS (0x30 | 3 = 0x33)
    // [rsp + 0x10] = RFLAGS (0x202 = IF enabled)
    // [rsp + 0x18] = RSP (user_stack)
    // [rsp + 0x20] = SS (0x28 | 3 = 0x2B)
    core::arch::asm!(
        "mov ax, 0x2B",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "push 0x2B",         // SS
        "push {0}",          // RSP
        "push 0x202",        // RFLAGS (IF=1)
        "push 0x33",         // CS
        "push {1}",          // RIP
        "iretq",
        in(reg) user_stack,
        in(reg) entry_point,
        options(noreturn)
    );
}
