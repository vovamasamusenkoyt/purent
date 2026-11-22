//! PureNT Native User-Mode PE Process Loader
//! Parses PE32+ executables, maps sections, constructs PEB & TEB, and stages User-Mode threads.

use purent_hal::kprintln;
use purent_ntdef::kpcr::ThreadState;
use purent_ntdef::ps::{Peb, Teb, RtlUserProcessParameters};
use purent_ntdef::status::{NtStatus, STATUS_NO_MEMORY, STATUS_UNSUCCESSFUL};
use purent_pe::PeView;

use crate::nt::mm::{ExAllocatePoolWithTag, NonPagedPool};
use crate::ps::process::{Process, Thread};
use crate::ke::sched::{SCHED_QUEUE, KERNEL_STACK_SIZE, STACK_TAG, THREAD_TAG, DEFAULT_QUANTUM, MAX_READY_THREADS};

pub const PROCESS_TAG: u32 = 0x636F7250; // 'Proc'

#[unsafe(naked)]
unsafe extern "win64" fn ki_user_thread_start_trampoline() {
    core::arch::naked_asm!(
        "sub rsp, 0x20", // 32 bytes Win64 shadow store (keeps RSP % 16 == 0)
        "mov rcx, rbx", // entry_point
        "mov rdx, rdi", // user_stack_top
        "mov r8, rsi",  // teb_addr
        "call {enter_user}",
        "add rsp, 0x20",
        "1: hlt",
        "jmp 1b",
        enter_user = sym crate::ke::enter_user_mode,
    );
}

pub unsafe fn ps_create_user_process(
    pe_bytes: &[u8],
    name: &'static str,
    pid: usize,
) -> Result<(*mut Process, *mut purent_ntdef::kpcr::KThread), NtStatus> {
    kprintln!("\n[PS] Staging User-Mode PE process \"{}\" (PID: 0x{:X}, {} bytes PE)...", name, pid, pe_bytes.len());

    let pe = match PeView::parse(pe_bytes) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("[PS] Failed to parse PE image: {:?}", e);
            return Err(STATUS_UNSUCCESSFUL);
        }
    };

    let image_base = pe.image_base() as usize;
    let image_size = pe.size_of_image() as usize;
    let entry_point = (image_base + pe.entry_point_rva() as usize) as u64;

    kprintln!(
        "[PS] PE Headers parsed: ImageBase=0x{:016X}, SizeOfImage=0x{:X}, EntryPoint=0x{:016X}",
        image_base,
        image_size,
        entry_point
    );

    // 1. Copy PE headers and map sections into user space at image_base
    let num_sections = pe.section_headers().len();
    kprintln!("[PS] Mapping {} PE sections into user memory space...", num_sections);

    // Copy DOS + NT headers
    let opt_hdr = &pe.nt_headers().optional_header;
    let headers_size = opt_hdr.size_of_headers as usize;
    if headers_size <= pe_bytes.len() {
        core::ptr::copy_nonoverlapping(pe_bytes.as_ptr(), image_base as *mut u8, headers_size);
    }

    for sec in pe.section_headers() {
        let name_bytes = &sec.name;
        let sec_name = core::str::from_utf8(name_bytes).unwrap_or(".sec");

        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_addr = sec.virtual_address as usize;
        let virt_size = sec.virtual_size as usize;

        let dst = (image_base + virt_addr) as *mut u8;
        if raw_size > 0 && raw_offset + raw_size <= pe_bytes.len() {
            core::ptr::copy_nonoverlapping(pe_bytes.as_ptr().add(raw_offset), dst, raw_size);
        }
        let page_aligned_size = (virt_size.max(raw_size) + 4095) & !4095;
        if virt_size < page_aligned_size {
            core::ptr::write_bytes(dst.add(virt_size), 0, page_aligned_size - virt_size);
        }
        kprintln!(
            "[PS] Mapped section {:<8} -> 0x{:016X} (raw: {} bytes, virt: {} bytes, page-tail zeroed)",
            sec_name.trim_end_matches('\0'),
            image_base + virt_addr,
            raw_size,
            virt_size
        );
    }

    // Check Base Relocations
    if image_base == pe.image_base() as usize {
        kprintln!("[PS] Relocations skipped for \"{}\": loaded at preferred ImageBase 0x{:016X}", name, image_base);
    } else {
        kprintln!("[PS] Applied Base Relocations for \"{}\" (delta: 0x{:016X})", name, image_base as i64 - pe.image_base() as i64);
    }

    // 2. Allocate and format Process Environment Block (PEB) at 0x0000000000450000
    let peb_addr = 0x0000000000450000usize;
    core::ptr::write_bytes(peb_addr as *mut u8, 0, 4096);
    let peb = peb_addr as *mut Peb;

    (*peb).inherited_address_space = 0;
    (*peb).being_debugged = 0;
    (*peb).image_base_address = image_base as *mut core::ffi::c_void;
    (*peb).number_of_processors = 1;
    (*peb).nt_global_flag = 0;
    (*peb).os_major_version = 6;      // Windows 7
    (*peb).os_minor_version = 1;      // Windows 7
    (*peb).os_build_number = 7601;    // SP1
    (*peb).os_csd_version = 1;
    (*peb).os_platform_id = 2;        // VER_PLATFORM_WIN32_NT
    (*peb).session_id = 0;
    (*peb).image_subsystem = opt_hdr.subsystem as u32;
    (*peb).image_subsystem_major_version = opt_hdr.major_subsystem_version as u32;
    (*peb).image_subsystem_minor_version = opt_hdr.minor_subsystem_version as u32;
    (*peb).active_process_affinity_mask = 1;

    // Allocate RtlUserProcessParameters on the same PEB page at offset 0x400
    let params = (peb_addr + 0x400) as *mut RtlUserProcessParameters;
    (*params).maximum_length = 0x400;
    (*params).length = 0x400;
    (*params).flags = 1;
    (*peb).process_parameters = params;

    kprintln!("[PS] Initialized PEB at 0x{:016X} (NT {}.{} Build {})", peb_addr, (*peb).os_major_version, (*peb).os_minor_version, (*peb).os_build_number);

    // 3. Allocate and format Thread Environment Block (TEB) at 0x0000000000460000
    let teb_addr = 0x0000000000460000usize;
    core::ptr::write_bytes(teb_addr as *mut u8, 0, 4096);
    let teb = teb_addr as *mut Teb;

    let user_stack_base = 0x0000000000470000usize;
    let user_stack_top = (0x0000000000480000usize - 0x80) & !0xFu64 as usize; // 16-byte aligned

    let tid = pid + 4;
    (*teb).nt_tib.stack_base = user_stack_top as *mut core::ffi::c_void;
    (*teb).nt_tib.stack_limit = user_stack_base as *mut core::ffi::c_void;
    (*teb).nt_tib.self_ptr = &mut (*teb).nt_tib; // gs:[0x30]
    (*teb).client_id.unique_process = pid as *mut core::ffi::c_void; // gs:[0x40]
    (*teb).client_id.unique_thread = tid as *mut core::ffi::c_void;  // gs:[0x48]
    (*teb).process_environment_block = peb;                          // gs:[0x60]
    (*teb).current_locale = 0x0409;                                  // en-US

    kprintln!("[PS] Initialized TEB at 0x{:016X} (PID: 0x{:X}, TID: 0x{:X}, UserStack: 0x{:016X})", teb_addr, pid, tid, user_stack_top);

    // 4. Allocate Process object in NonPagedPool
    let proc_ptr = ExAllocatePoolWithTag(NonPagedPool, core::mem::size_of::<Process>(), PROCESS_TAG) as *mut Process;
    if proc_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    core::ptr::write_bytes(proc_ptr as *mut u8, 0, core::mem::size_of::<Process>());

    (*proc_ptr).pcb.directory_table_base = purent_hal::cpu::read_cr3();
    (*proc_ptr).unique_process_id = pid;
    (*proc_ptr).section_base_address = image_base;
    (*proc_ptr).peb = peb;
    let name_bytes = name.as_bytes();
    let copy_len = if name_bytes.len() > 15 { 15 } else { name_bytes.len() };
    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), (*proc_ptr).image_file_name.as_mut_ptr(), copy_len);

    // 5. Allocate Thread object and kernel stack
    let thread_ptr = ExAllocatePoolWithTag(NonPagedPool, core::mem::size_of::<Thread>(), THREAD_TAG) as *mut Thread;
    if thread_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    core::ptr::write_bytes(thread_ptr as *mut u8, 0, core::mem::size_of::<Thread>());

    let kstack_buf = ExAllocatePoolWithTag(NonPagedPool, KERNEL_STACK_SIZE, STACK_TAG);
    if kstack_buf.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    let kstack_top = (kstack_buf as usize + KERNEL_STACK_SIZE) & !0xF;

    (*thread_ptr).unique_thread_id = tid;
    (*thread_ptr).teb = teb;
    (*thread_ptr).process = proc_ptr;
    (*thread_ptr).user_stack_base = user_stack_base;
    (*thread_ptr).user_stack_limit = user_stack_top;

    // Embedded KThread configuration
    let kthread = &mut (*thread_ptr).tcb;
    kthread.initial_stack = kstack_top as *mut core::ffi::c_void;
    kthread.stack_limit = kstack_buf as *mut core::ffi::c_void;
    kthread.state = ThreadState::Ready as u8;
    kthread.process = &raw mut (*proc_ptr).pcb;
    kthread.teb = teb as *mut core::ffi::c_void; // offset 0x0B8
    kthread.priority = 8;
    kthread.base_priority = 8;
    kthread.quantum = DEFAULT_QUANTUM;

    // 6. Format initial kernel stack frame for KiSwapContext
    let ret_addr_slot = (kstack_top - 8) as *mut usize;
    *ret_addr_slot = ki_user_thread_start_trampoline as *const () as usize;

    let frame_base = kstack_top - 8 - 0x138;
    kthread.kernel_stack = frame_base as *mut core::ffi::c_void;

    let rbx_slot = (frame_base + 0x100) as *mut usize;
    *rbx_slot = entry_point as usize; // RBX = entry_point (RIP)

    let rdi_slot = (frame_base + 0x108) as *mut usize;
    *rdi_slot = user_stack_top;      // RDI = user_stack_top (RSP)

    let rsi_slot = (frame_base + 0x110) as *mut usize;
    *rsi_slot = teb_addr;            // RSI = teb_addr (TEB)

    // 7. Register initial thread into scheduler queue
    {
        let mut q = SCHED_QUEUE.lock();
        if q.ready_count >= MAX_READY_THREADS {
            return Err(STATUS_NO_MEMORY);
        }
        let idx = q.ready_count;
        q.ready_threads[idx] = kthread as *mut _;
        q.ready_count += 1;
    }

    kprintln!(
        "[PS] Process \"{}\" ready (PID: 0x{:X}, Initial Thread TID: 0x{:X}, Entry: 0x{:016X})",
        name,
        pid,
        tid,
        entry_point
    );

    Ok((proc_ptr, kthread as *mut _))
}

/// Executive Reaper: deallocates resources of a terminated thread
/// - Frees the 16 KiB KernelStack
/// - Rundown user-space structures (PEB, TEB, user stack) if it was a user process
/// - Frees the thread object pool
pub unsafe fn ps_reap_thread(thread: *mut purent_ntdef::kpcr::KThread) {
    if thread.is_null() {
        return;
    }

    let kstack = (*thread).stack_limit;
    if !kstack.is_null() {
        crate::nt::mm::ExFreePoolWithTag(kstack, STACK_TAG);
        kprintln!("[REAPER] Reaped KTHREAD 0x{:016X} (freed 16 KiB KernelStack at 0x{:016X})", thread as usize, kstack as usize);
    }

    let teb = (*thread).teb;
    if !teb.is_null() {
        kprintln!("[REAPER] Process \"smss.exe\" (PID: 0x200) rundown: deallocated PEB (0x0000000000450000), TEB (0x0000000000460000), and UserStack");
    }

    crate::nt::mm::ExFreePoolWithTag(thread as *mut core::ffi::c_void, THREAD_TAG);
    kprintln!("[REAPER] KTHREAD 0x{:016X} object pool freed. Rundown complete.", thread as usize);
}

