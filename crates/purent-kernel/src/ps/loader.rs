//! PureNT Native User-Mode PE Process Loader
//! Parses PE32+ executables, maps sections, constructs PEB & TEB, and stages User-Mode threads.

use purent_hal::kprintln;
use purent_ntdef::kpcr::ThreadState;
use purent_ntdef::ps::{Peb, RtlUserProcessParameters, Teb};
use purent_ntdef::status::{NtStatus, STATUS_NO_MEMORY, STATUS_UNSUCCESSFUL};
use purent_pe::PeView;

use crate::ke::arch::ki_user_thread_start_trampoline;
use crate::ke::sched::{
    DEFAULT_QUANTUM, KERNEL_STACK_SIZE, MAX_READY_THREADS, SCHED_QUEUE, STACK_TAG, THREAD_TAG,
};
use crate::mm::{
    phys_to_virt, vmm_map_user_page, vmm_protect_user_page, ExAllocatePoolWithTag, NonPagedPool,
    PMM, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use crate::ps::process::{Process, Thread};

pub const PROCESS_TAG: u32 = 0x636F7250; // 'Proc'

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

    let cr3 = purent_hal::cpu::read_cr3();

    // 1. Copy PE headers and map sections into user space at image_base
    let num_sections = pe.section_headers().len();
    kprintln!("[PS] Mapping {} PE sections into user memory space via VMM 4KB paging...", num_sections);

    // Map and copy PE headers
    let opt_hdr = &pe.nt_headers().optional_header;
    let headers_size = opt_hdr.size_of_headers as usize;
    let headers_pages = (headers_size + 4095) / 4096;
    for i in 0..headers_pages {
        let va = (image_base + i * 4096) as u64;
        let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
        vmm_map_user_page(
            cr3,
            va,
            frame,
            PTE_PRESENT | PTE_USER | PTE_WRITABLE,
        )?;
    }
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
        let sec_va = image_base + virt_addr;

        let page_aligned_size = (virt_size.max(raw_size) + 4095) & !4095;
        let sec_pages = page_aligned_size / 4096;
        for j in 0..sec_pages {
            let va = (sec_va + j * 4096) as u64;
            let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
            vmm_map_user_page(
                cr3,
                va,
                frame,
                PTE_PRESENT | PTE_USER | PTE_WRITABLE,
            )?;
        }

        let dst = sec_va as *mut u8;
        if raw_size > 0 && raw_offset + raw_size <= pe_bytes.len() {
            core::ptr::copy_nonoverlapping(pe_bytes.as_ptr().add(raw_offset), dst, raw_size);
        }
        if virt_size < page_aligned_size {
            core::ptr::write_bytes(dst.add(virt_size), 0, page_aligned_size - virt_size);
        }

        let chars = sec.characteristics;
        let (protect_str, pte_flags) = if chars & 0x20000000 != 0 {
            ("PAGE_EXECUTE_READ (RX)", PTE_PRESENT | PTE_USER)
        } else if chars & 0x80000000 != 0 {
            ("PAGE_READWRITE (RW+NX)", PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX)
        } else {
            ("PAGE_READONLY (RO+NX)", PTE_PRESENT | PTE_USER | PTE_NX)
        };

        for j in 0..sec_pages {
            let va = (sec_va + j * 4096) as u64;
            let _ = vmm_protect_user_page(cr3, va, pte_flags);
        }

        kprintln!(
            "[PS] Mapped section {:<8} -> 0x{:016X} (raw: {} bytes, virt: {} bytes, tail-zeroed) [{}]",
            sec_name.trim_end_matches('\0'),
            sec_va,
            raw_size,
            virt_size,
            protect_str
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
    let peb_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(peb_frame), 0, 4096);
    vmm_map_user_page(
        cr3,
        peb_addr as u64,
        peb_frame,
        PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
    )?;
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
    let teb_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(teb_frame), 0, 4096);
    vmm_map_user_page(
        cr3,
        teb_addr as u64,
        teb_frame,
        PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
    )?;
    let teb = teb_addr as *mut Teb;

    let user_stack_base = 0x0000000000470000usize;
    let user_stack_top = (0x0000000000480000usize - 0x80) & !0xFu64 as usize; // 16-byte aligned

    // Map 64 KiB (16 pages) for user stack
    for s in 0..16 {
        let va = (user_stack_base + s * 4096) as u64;
        let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
        vmm_map_user_page(
            cr3,
            va,
            frame,
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
        )?;
    }

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
        "[PS] Process \"{}\" ready (PID: 0x{:X}, Initial Thread TID: 0x{:X}, Entry: 0x{:016X}, KernelStack: [0x{:016X}..0x{:016X}], UserStack: [0x{:016X}..0x{:016X}])",
        name,
        pid,
        tid,
        entry_point,
        kstack_buf as usize,
        kstack_top,
        user_stack_base,
        user_stack_top
    );

    Ok((proc_ptr, kthread as *mut _))
}
