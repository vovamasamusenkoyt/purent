//! x86_64 Low-Level CPU Gates and Architecture Context
//! Houses all naked hardware assembly routines: syscall vector, context switch, and thread trampolines.

use purent_ntdef::kpcr::KThread;

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "push rcx",
        "push rax",
        "cmp rax, 0x1000",
        "lea rcx, [rsp + 24]",
        "jb 2f",
        "1:",
        "sub rcx, 0x1000",
        "test byte ptr [rcx], 0",
        "sub rax, 0x1000",
        "cmp rax, 0x1000",
        "ja 1b",
        "2:",
        "sub rcx, rax",
        "test byte ptr [rcx], 0",
        "pop rax",
        "pop rcx",
        "ret",
    );
}

#[unsafe(naked)]
pub unsafe extern "win64" fn ki_thread_start_trampoline() {
    core::arch::naked_asm!(
        "sub rsp, 0x20", // 32 bytes Win64 shadow store (keeps RSP % 16 == 0)
        "mov rcx, rdi",  // context passed in RDI -> Windows x64 RCX argument 1
        "call rbx",      // routine passed in RBX
        "add rsp, 0x20",
        "1: hlt",
        "jmp 1b",
    );
}

#[unsafe(naked)]
pub unsafe extern "win64" fn ki_user_thread_start_trampoline() {
    core::arch::naked_asm!(
        "sub rsp, 0x20", // 32 bytes Win64 shadow store (keeps RSP % 16 == 0)
        "mov rcx, rbx", // entry_point
        "mov rdx, rdi", // user_stack_top
        "mov r8, rsi",  // teb_addr
        "call {enter_user}",
        "add rsp, 0x20",
        "1: hlt",
        "jmp 1b",
        enter_user = sym enter_user_mode,
    );
}

/// Transition from Ring 0 (Kernel) to Ring 3 (User-Mode) via `iretq`
pub unsafe fn enter_user_mode(entry_point: u64, user_stack: u64, teb: u64) -> ! {
    purent_hal::kprintln!("[KE] Entering User-Mode (Ring 3) at RIP=0x{:016X}, RSP=0x{:016X}, TEB=0x{:016X}...", entry_point, user_stack, teb);

    // 1. Put user TEB into IA32_KERNEL_GS_BASE
    purent_hal::cpu::wrmsr(purent_hal::cpu::IA32_KERNEL_GS_BASE, teb);

    // 2. Execute swapgs so IA32_GS_BASE becomes TEB and IA32_KERNEL_GS_BASE becomes KPCR!
    // 3. Execute iretq into Ring 3!
    let seg_selector: u64 = 0x2B;
    core::arch::asm!(
        "mov ds, {seg:x}",
        "mov es, {seg:x}",
        "mov fs, {seg:x}",
        "swapgs",            // Swap GS: IA32_GS_BASE = user TEB, IA32_KERNEL_GS_BASE = KPCR
        "push 0x2B",         // SS (0x28 | 3)
        "push {stack}",      // RSP (user_stack)
        "push 0x202",        // RFLAGS (IF=1)
        "push 0x33",         // CS (0x30 | 3)
        "push {rip}",        // RIP (entry_point)
        "iretq",
        seg = in(reg) seg_selector,
        stack = in(reg) user_stack,
        rip = in(reg) entry_point,
        options(noreturn)
    );
}

/// Hardware entry point for Ring 3 `syscall` instruction.
/// Matches Windows NT `KiSystemCall64` ABI, pushes a `TrapFrame`, and calls `ki_system_call_dispatch`.
#[unsafe(naked)]
pub unsafe extern "C" fn ki_system_call_64() {
    core::arch::naked_asm!(
        // 1. Swap user GS base with Kernel KPCR
        "swapgs",

        // 2. Save user RSP in KPCR scratch slot (gs:[0x10])
        "mov gs:[0x10], rsp",

        // 3. Switch RSP to Kernel Stack from KPCR PRCB RspBase (gs:[0x1A8])
        "mov rsp, gs:[0x1A8]",

        // 4. Construct TrapFrame on kernel stack:
        // Hardware frame (matches iretq/sysretq layout)
        "push 0x2B",                // SS (0x28 | 3)
        "push qword ptr gs:[0x10]", // User RSP
        "push r11",                 // User RFLAGS
        "push 0x33",                // User CS (0x30 | 3)
        "push rcx",                 // User RIP

        // Syscall parameters and rax
        "push rax",                 // rax (Syscall Number)
        "push r9",                  // r9  (Arg 4)
        "push r8",                  // r8  (Arg 3)
        "push rdx",                 // rdx (Arg 2)
        "push r10",                 // r10 (Arg 1)

        // Callee-saved registers
        "push rbp",
        "push rbx",
        "push rsi",
        "push rdi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // 5. Set PreviousMode in CurrentThread (gs:[0x188] + 0x1F6) to UserMode (1)
        "mov r11, gs:[0x188]",
        "test r11, r11",
        "jz 1f",
        "mov byte ptr [r11 + 0x1F6], 1",
        "1:",

        // 6. Enable CPU interrupts during syscall execution
        "sti",

        // 7. Pass &mut TrapFrame (in RSP) to pure Rust ki_system_call_dispatch
        "mov rcx, rsp",
        "sub rsp, 0x20",            // 32-byte Win64 shadow store
        "call {dispatch}",
        "add rsp, 0x20",

        // Disable interrupts for atomic user frame restoration
        "cli",

        // 8. Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rdi",
        "pop rsi",
        "pop rbx",
        "pop rbp",

        // Restore syscall parameters & rax (return status now in rax!)
        "pop r10",
        "pop rdx",
        "pop r8",
        "pop r9",
        "pop rax",

        // 9. Restore user trap frame
        "pop rcx",                  // User RIP for sysretq
        "add rsp, 8",               // Skip User CS
        "pop r11",                  // User RFLAGS for sysretq
        "pop rdx",                  // User RSP
        "add rsp, 8",               // Skip User SS
        "mov rsp, rdx",             // Switch back to User RSP

        // 10. Swap GS back to user space
        "swapgs",

        // 11. Fast return to Ring 3 (sysretq)
        ".byte 0x48, 0x0F, 0x07",

        dispatch = sym super::dispatch::ki_system_call_dispatch,
    );
}

/// Exact replica of Windows NT 6.1 x64 KiSwapContext / SwapContext
#[unsafe(naked)]
#[allow(non_snake_case)]
pub unsafe extern "win64" fn KiSwapContext(
    current_thread: *mut KThread,
    next_thread: *mut KThread,
) {
    core::arch::naked_asm!(
        "cli",

        // 1. Allocate 0x138 stack frame (matching ntoskrnl KiSwapContext)
        "sub rsp, 0x138",

        // 2. Save non-volatile XMM registers (XMM6 - XMM15)
        "movdqu [rsp + 0x30], xmm6",
        "movdqu [rsp + 0x40], xmm7",
        "movdqu [rsp + 0x50], xmm8",
        "movdqu [rsp + 0x60], xmm9",
        "movdqu [rsp + 0x70], xmm10",
        "movdqu [rsp + 0x80], xmm11",
        "movdqu [rsp + 0xA0], xmm12",
        "movdqu [rsp + 0xB0], xmm13",
        "movdqu [rsp + 0xC0], xmm14",
        "movdqu [rsp + 0xD0], xmm15",

        // 3. Save callee-saved GPRs (RBX, RDI, RSI, R12, R13, R14, R15)
        "mov [rsp + 0x100], rbx",
        "mov [rsp + 0x108], rdi",
        "mov [rsp + 0x110], rsi",
        "mov [rsp + 0x118], r12",
        "mov [rsp + 0x120], r13",
        "mov [rsp + 0x128], r14",
        "mov [rsp + 0x130], r15",

        // 4. Set up registers for SwapContext:
        // RDI = CurrentThread, RSI = NextThread, RBX = KPCR.CurrentPrcb (gs:[0x20])
        "mov rdi, rcx",
        "mov rsi, rdx",
        "mov rbx, gs:[0x20]",

        // 5. Save the outgoing stack and switch to the incoming address space.
        "mov [rdi + 0x38], rsp",
        // Switch page tables before accessing the incoming stack. The boot
        // thread still uses the low identity-mapped UEFI stack.
        "mov rax, [rsi + 0x70]",
        "cmp rax, [rdi + 0x70]",
        "je 2f",
        "test rax, rax",
        "jz 2f",
        "mov rdx, [rax + 0x28]",
        "mov cr3, rdx",
        "2:",
        "mov rsp, [rsi + 0x38]",

        // 6. Update Prcb.CurrentThread (gs:[0x188]) to NextThread
        "mov gs:[0x188], rsi",

        // 7. Update Prcb.RspBase (TSS RSP0 target at PRCB + 0x28) to NextThread->InitialStack
        "mov rax, [rsi + 0x28]",
        "test rbx, rbx",
        "jz 1f",
        "mov [rbx + 0x28], rax",
        "1:",
        "push rsi",
        "push rdi",
        "sub rsp, 0x20", // 32 bytes shadow store for Win64 ABI
        "mov rcx, rax",
        "call {set_rsp0}",
        "add rsp, 0x20",
        "pop rdi",
        "pop rsi",

        // 8. Mark the incoming thread Running; the scheduler owns the outgoing state.
        "mov byte ptr [rsi + 0x49], 2",
        "inc dword ptr [rsi + 0x138]",

        // 10. Update IA32_KERNEL_GS_BASE if NextThread has a TEB (offset 0xB8)
        "mov r8, [rsi + 0x0B8]",
        "test r8, r8",
        "jz 3f",
        "mov ecx, 0xC0000102",
        "mov eax, r8d",
        "shr r8, 32",
        "mov edx, r8d",
        "wrmsr",
        "3:",

        // 11. Restore GPRs from new thread's stack
        "mov rbx, [rsp + 0x100]",
        "mov rdi, [rsp + 0x108]",
        "mov rsi, [rsp + 0x110]",
        "mov r12, [rsp + 0x118]",
        "mov r13, [rsp + 0x120]",
        "mov r14, [rsp + 0x128]",
        "mov r15, [rsp + 0x130]",

        // 12. Restore XMM registers
        "movdqu xmm6, [rsp + 0x30]",
        "movdqu xmm7, [rsp + 0x40]",
        "movdqu xmm8, [rsp + 0x50]",
        "movdqu xmm9, [rsp + 0x60]",
        "movdqu xmm10, [rsp + 0x70]",
        "movdqu xmm11, [rsp + 0x80]",
        "movdqu xmm12, [rsp + 0xA0]",
        "movdqu xmm13, [rsp + 0xB0]",
        "movdqu xmm14, [rsp + 0xC0]",
        "movdqu xmm15, [rsp + 0xD0]",

        "add rsp, 0x138",
        "sti",
        "ret",

        set_rsp0 = sym purent_hal::gdt::set_rsp0,
    );
}
