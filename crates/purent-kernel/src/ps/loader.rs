//! PureNT Native User-Mode PE Process Loader
//! Parses PE32+ executables, maps sections, constructs PEB & TEB, and stages User-Mode threads.

use purent_hal::kprintln;
use purent_ntdef::kpcr::ThreadState;
use purent_ntdef::ps::{Peb, RtlUserProcessParameters, Teb};
use purent_ntdef::status::{NtStatus, STATUS_NO_MEMORY, STATUS_UNSUCCESSFUL};
use purent_pe::PeView;

use purent_ntdef::win32_modules::BUILTIN_MODULES;
use purent_pe::NamedExport;

use crate::ke::arch::ki_user_thread_start_trampoline;
use crate::ke::sched::{
    DEFAULT_QUANTUM, KERNEL_STACK_SIZE, MAX_READY_THREADS, SCHED_QUEUE, STACK_TAG, THREAD_TAG,
};
use crate::mm::{
    phys_to_virt, vmm_map_owned_user_page, vmm_map_user_page, vmm_protect_user_page, ExAllocatePoolWithTag, NonPagedPool,
    PMM, PTE_NX, PTE_OWNED, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use crate::ps::process::{Process, Thread};

pub const PROCESS_TAG: u32 = 0x636F7250; // 'Proc'

pub unsafe fn ps_create_user_process(
    pe_bytes: &[u8],
    name: &'static str,
    pid: usize,
    environment_base: usize,
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
    let peb_addr = environment_base;
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
    let teb_addr = environment_base + 0x10000;
    let teb_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(teb_frame), 0, 4096);
    vmm_map_user_page(
        cr3,
        teb_addr as u64,
        teb_frame,
        PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
    )?;
    let teb = teb_addr as *mut Teb;

    let user_stack_base = environment_base + 0x20000;
    let user_stack_top = (user_stack_base + 0x10000 - 0x80) & !0xFu64 as usize; // 16-byte aligned

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

/// Map the read-only user alias of KUSER_SHARED_DATA used by Windows GUI executables.
pub unsafe fn ps_map_user_shared_data(cr3: u64) -> Result<(), NtStatus> {
    let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
    let result = vmm_map_owned_user_page(
        cr3, 0x7FFE0000, frame, PTE_PRESENT | PTE_USER | PTE_NX,
    );
    if result.is_err() {
        PMM.lock().free_frame(frame);
    }
    result
}

const WIN32_MODULES: &[(&str, &[u8])] = &[
    ("kernel32.dll", include_bytes!("../../../../target/esp/kernel32.dll")),
    ("kernelbase.dll", include_bytes!("../../../../target/esp/kernelbase.dll")),
    ("ntdll.dll", include_bytes!("../../../../target/esp/ntdll.dll")),
    ("msvcrt.dll", include_bytes!("../../../../target/esp/msvcrt.dll")),
    ("winbrand.dll", include_bytes!("../../../../target/esp/winbrand.dll")),
    ("user32.dll", include_bytes!("../../../../target/esp/user32.dll")),
    ("shell32.dll", include_bytes!("../../../../target/esp/shell32.dll")),
];

unsafe fn map_win32_image(cr3: u64, bytes: &[u8], pe: &PeView<'_>) -> Result<(), NtStatus> {
    let base = pe.image_base();
    let image_size = pe.size_of_image() as usize;
    let headers = pe.nt_headers().optional_header.size_of_headers as usize;
    let header_bytes = bytes.get(..headers).filter(|_| headers <= image_size).ok_or(STATUS_UNSUCCESSFUL)?;
    for section in pe.section_headers() {
        let rva = section.virtual_address as usize;
        let size = section.virtual_size.max(section.size_of_raw_data) as usize;
        let raw = section.pointer_to_raw_data as usize;
        if rva + size > image_size || raw + section.size_of_raw_data as usize > bytes.len() {
            return Err(STATUS_UNSUCCESSFUL);
        }
    }

    for offset in (0..image_size).step_by(4096) {
        let result = (|| {
            let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
            if let Err(status) = vmm_map_owned_user_page(cr3, base + offset as u64, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX) {
                PMM.lock().free_frame(frame);
                return Err(status);
            }
            Ok(())
        })();
        if let Err(status) = result {
            for prior in (0..offset).step_by(4096) {
                if let Some(frame) = crate::mm::vmm_unmap_user_page(cr3, base + prior as u64) {
                    PMM.lock().free_frame(frame);
                }
            }
            return Err(status);
        }
    }

    let copy = |rva: usize, bytes: &[u8]| {
        let mut copied = 0;
        while copied < bytes.len() {
            let offset = rva + copied;
            let page_offset = offset & 4095;
            let count = (4096 - page_offset).min(bytes.len() - copied);
            let (frame, _) = crate::mm::vmm_query_user_page(cr3, base + (offset & !4095) as u64)
                .expect("newly mapped image page");
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(copied), phys_to_virt::<u8>(frame).add(page_offset), count,
            );
            copied += count;
        }
    };
    copy(0, header_bytes);
    for section in pe.section_headers() {
        let raw = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        copy(section.virtual_address as usize, &bytes[raw..raw + size]);
    }
    Ok(())
}

unsafe fn protect_win32_image(cr3: u64, pe: &PeView<'_>) -> Result<(), NtStatus> {
    let base = pe.image_base() as usize;
    for offset in (0..pe.nt_headers().optional_header.size_of_headers as usize).step_by(4096) {
        vmm_protect_user_page(cr3, (base + offset) as u64, PTE_PRESENT | PTE_USER | PTE_NX)?;
    }
    for sec in pe.section_headers() {
        let virt_addr = sec.virtual_address as usize;
        let virt_size = sec.virtual_size as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let sec_va = base + virt_addr;
        let page_aligned_size = (virt_size.max(raw_size) + 4095) & !4095;
        let sec_pages = page_aligned_size / 4096;

        let chars = sec.characteristics;
        let pte_flags = if chars & 0x20000000 != 0 {
            PTE_PRESENT | PTE_USER
        } else if chars & 0x80000000 != 0 {
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX
        } else {
            PTE_PRESENT | PTE_USER | PTE_NX
        };

        for j in 0..sec_pages {
            let va = (sec_va + j * 4096) as u64;
            vmm_protect_user_page(cr3, va, pte_flags)?;
        }
    }

    Ok(())
}

unsafe fn module_mapped(cr3: u64, address: u64) -> bool {
    crate::mm::vmm_query_user_page(cr3, address)
        .is_some_and(|(_, flags)| flags & PTE_OWNED != 0)
}

fn catalog_image(index: usize) -> Option<(&'static str, &'static [u8], PeView<'static>)> {
    let &(name, address) = BUILTIN_MODULES.get(index)?;
    let &(_, bytes) = WIN32_MODULES.iter().find(|&&(registered, _)| name == registered)?;
    let pe = PeView::parse(bytes).ok()?;
    (pe.image_base() == address as u64).then_some((name, bytes, pe))
}

pub unsafe fn ps_map_win32_module(index: usize) -> NtStatus {
    map_win32_module(purent_hal::cpu::read_cr3(), index)
}

unsafe fn map_win32_module(cr3: u64, index: usize) -> NtStatus {
    let Some((name, bytes, pe)) = catalog_image(index) else {
        return purent_ntdef::status::STATUS_INVALID_PARAMETER;
    };
    if module_mapped(cr3, pe.image_base()) {
        return purent_ntdef::status::STATUS_SUCCESS;
    }
    match map_win32_image(cr3, bytes, &pe) {
        Ok(()) => {
            let base = pe.image_base();
            kprintln!("[PS] Mapped {} at 0x{:016X}", name, base);
            purent_ntdef::status::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe fn ps_seal_win32_image(image: u64) -> NtStatus {
    use purent_ntdef::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
    let pe = if image == purent_ntdef::syscall::CURRENT_EXECUTABLE_IMAGE {
        let bytes = match crate::ps::current_process_id() {
            Some(crate::win32k::CONSOLE_CLIENT_PID) => crate::CMD_EXE_BYTES,
            Some(pid) => match super::builtin::image_for_pid(pid) {
                Some(bytes) => bytes,
                None => return STATUS_INVALID_PARAMETER,
            },
            _ => return STATUS_INVALID_PARAMETER,
        };
        PeView::parse(bytes).ok()
    } else if let Some((_, _, pe)) = catalog_image(image as usize) {
        if !module_mapped(purent_hal::cpu::read_cr3(), pe.image_base()) {
            return STATUS_INVALID_PARAMETER;
        }
        Some(pe)
    } else {
        None
    };
    let Some(pe) = pe else { return STATUS_INVALID_PARAMETER };
    protect_win32_image(purent_hal::cpu::read_cr3(), &pe).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

pub unsafe fn ps_load_ntdll(cr3: u64) -> Result<usize, NtStatus> {
    let index = BUILTIN_MODULES.iter().position(|&(name, _)| name == "ntdll.dll").ok_or(STATUS_UNSUCCESSFUL)?;
    let status = map_win32_module(cr3, index);
    if status < 0 {
        return Err(status);
    }
    let (_, _, pe) = catalog_image(index).ok_or(STATUS_UNSUCCESSFUL)?;
    protect_win32_image(cr3, &pe)?;
    match pe.named_export(b"PureNtLdrStart", false) {
        Some(NamedExport::Address(rva)) => Ok(pe.image_base() as usize + rva as usize),
        _ => Err(STATUS_UNSUCCESSFUL),
    }
}

const WIN32_STACK_PAGES: usize = 64;

fn environment_page(base: usize, page: usize) -> u64 {
    match page {
        0 => base as u64,
        1 => (base + 0x10000) as u64,
        _ => (base + 0x20000 + (page - 2) * 4096) as u64,
    }
}

unsafe fn release_page(cr3: u64, address: u64) {
    if let Some(frame) = crate::mm::vmm_unmap_user_page(cr3, address) {
        PMM.lock().free_frame(frame);
    }
}

unsafe fn release_win32_pages(cr3: u64, base: u64, size: usize, environment: usize, pages: usize) {
    for offset in (0..size).step_by(4096) {
        release_page(cr3, base + offset as u64);
    }
    for page in 0..pages {
        release_page(cr3, environment_page(environment, page));
    }
}

struct Win32Setup {
    cr3: u64,
    image: (u64, usize),
    environment: usize,
    mapped_pages: usize,
    allocations: [(*mut core::ffi::c_void, u32); 3],
}

impl Win32Setup {
    unsafe fn map_environment(&mut self) -> Result<(), NtStatus> {
        for page in 0..2 + WIN32_STACK_PAGES {
            let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
            let address = environment_page(self.environment, page);
            if let Err(status) = vmm_map_owned_user_page(self.cr3, address, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX) {
                PMM.lock().free_frame(frame);
                return Err(status);
            }
            self.mapped_pages += 1;
        }
        Ok(())
    }
}

impl Drop for Win32Setup {
    fn drop(&mut self) {
        unsafe {
            for &(allocation, tag) in &self.allocations {
                if !allocation.is_null() {
                    crate::mm::ExFreePoolWithTag(allocation, tag);
                }
            }
            release_win32_pages(self.cr3, self.image.0, self.image.1, self.environment, self.mapped_pages);
        }
    }
}

pub unsafe fn ps_create_win32_process(
    pe_bytes: &[u8],
    name: &'static str,
    pid: usize,
    environment_base: usize,
    loader_entry: usize,
    cr3: u64,
) -> Result<(*mut Process, *mut purent_ntdef::kpcr::KThread), NtStatus> {
    kprintln!("[PS] Staging Win32 process {} (PID: 0x{:X})", name, pid);

    // Map the executable before handing control to NTDLL.
    let image = PeView::parse(pe_bytes).map_err(|e| {
        kprintln!("[PS] Failed to parse {} PE: {:?}", name, e);
        STATUS_UNSUCCESSFUL
    })?;
    let image_base = image.image_base() as usize;
    let image_entry = (image_base + image.entry_point_rva() as usize) as u64;

    kprintln!(
        "[PS] Mapping {} at ImageBase 0x{:016X}, EntryPoint 0x{:016X}...",
        name,
        image_base,
        image_entry
    );

    let opt_hdr = &image.nt_headers().optional_header;
    map_win32_image(cr3, pe_bytes, &image)?;
    let mut setup = Win32Setup {
        cr3, image: (image.image_base(), image.size_of_image() as usize),
        environment: environment_base, mapped_pages: 0,
        allocations: [(core::ptr::null_mut(), 0); 3],
    };
    setup.map_environment()?;

    // 4. Initialize Process Environment Block (PEB) at 0x0000000000550000
    let peb_addr = environment_base;
    let kernel_page = |address: usize| {
        let (frame, _) = crate::mm::vmm_query_user_page(cr3, address as u64)
            .expect("newly mapped process environment page");
        phys_to_virt::<u8>(frame)
    };
    let peb_page = kernel_page(peb_addr);
    let peb = peb_page.cast::<Peb>();

    (*peb).inherited_address_space = 0;
    (*peb).being_debugged = 0;
    (*peb).image_base_address = image_base as *mut core::ffi::c_void;
    (*peb).number_of_processors = 1;
    (*peb).nt_global_flag = 0;
    (*peb).os_major_version = 6;      // Windows 7
    (*peb).os_minor_version = 1;      // SP1
    (*peb).os_build_number = 7601;
    (*peb).os_csd_version = 1;
    (*peb).os_platform_id = 2;        // VER_PLATFORM_WIN32_NT
    (*peb).session_id = 0;
    (*peb).image_subsystem = opt_hdr.subsystem as u32;
    (*peb).image_subsystem_major_version = 6;
    (*peb).image_subsystem_minor_version = 1;
    (*peb).active_process_affinity_mask = 1;

    let params = peb_page.add(0x400).cast::<RtlUserProcessParameters>();
    (*params).maximum_length = 0x400;
    (*params).length = 0x400;
    (*params).flags = 1;
    (*params).console_handle = 1 as *mut core::ffi::c_void;
    (*params).standard_input = 3 as *mut core::ffi::c_void;
    (*params).standard_output = 4 as *mut core::ffi::c_void;
    (*params).standard_error = 4 as *mut core::ffi::c_void;

    let curdir_buf = peb_page.add(0x600).cast::<u16>();
    let curdir_str = [ 'C' as u16, ':' as u16, '\\' as u16, 0 ];
    for i in 0..curdir_str.len() { *curdir_buf.add(i) = curdir_str[i]; }
    (*params).current_directory_path.length = 6;
    (*params).current_directory_path.maximum_length = 8;
    (*params).current_directory_path.buffer = (peb_addr + 0x600) as *mut u16;

    let img_buf = peb_page.add(0x680).cast::<u16>();
    let directory = b"C:\\Windows\\System32\\";
    for (index, byte) in directory.iter().chain(name.as_bytes()).enumerate() {
        *img_buf.add(index) = *byte as u16;
    }
    let image_chars = directory.len() + name.len();
    (*params).image_path_name.length = (image_chars * 2) as u16;
    (*params).image_path_name.maximum_length = ((image_chars + 1) * 2) as u16;
    (*params).image_path_name.buffer = (peb_addr + 0x680) as *mut u16;

    let cmdline_buf = peb_page.add(0x700).cast::<u16>();
    for (index, byte) in name.bytes().enumerate() {
        *cmdline_buf.add(index) = byte as u16;
    }
    (*params).command_line.length = (name.len() * 2) as u16;
    (*params).command_line.maximum_length = ((name.len() + 1) * 2) as u16;
    (*params).command_line.buffer = (peb_addr + 0x700) as *mut u16;

    (*peb).process_parameters = (peb_addr + 0x400) as *mut RtlUserProcessParameters;

    kprintln!("[PS] Initialized PEB at 0x{:016X} (NT {}.{} Build {})", peb_addr, (*peb).os_major_version, (*peb).os_minor_version, (*peb).os_build_number);

    // 5. Initialize Thread Environment Block (TEB) at 0x0000000000560000
    let teb_addr = environment_base + 0x10000;
    let teb = kernel_page(teb_addr).cast::<Teb>();

    let user_stack_base = environment_base + 0x20000;
    let stack_end = user_stack_base + 0x40000;
    let user_stack_top = (stack_end - 0x80) & !0xFu64 as usize;

    let tid = pid + 4;
    (*teb).nt_tib.stack_base = stack_end as *mut core::ffi::c_void;
    (*teb).nt_tib.stack_limit = user_stack_base as *mut core::ffi::c_void;
    (*teb).nt_tib.self_ptr = teb_addr as *mut _;
    (*teb).client_id.unique_process = pid as *mut core::ffi::c_void;
    (*teb).client_id.unique_thread = tid as *mut core::ffi::c_void;
    (*teb).process_environment_block = peb_addr as *mut Peb;
    (*teb).current_locale = 0x0409;

    kprintln!("[PS] Initialized TEB at 0x{:016X} (PID: 0x{:X}, TID: 0x{:X}, UserStack: 0x{:016X})", teb_addr, pid, tid, user_stack_top);

    // 6. Allocate Process & Thread objects
    let proc_ptr = ExAllocatePoolWithTag(NonPagedPool, core::mem::size_of::<Process>(), PROCESS_TAG) as *mut Process;
    if proc_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    setup.allocations[0] = (proc_ptr.cast(), PROCESS_TAG);
    core::ptr::write_bytes(proc_ptr as *mut u8, 0, core::mem::size_of::<Process>());

    (*proc_ptr).pcb.directory_table_base = cr3;
    (*proc_ptr).unique_process_id = pid;
    (*proc_ptr).section_base_address = image_base;
    (*proc_ptr).peb = peb_addr as *mut Peb;
    let name_bytes = name.as_bytes();
    let copy_len = if name_bytes.len() > 15 { 15 } else { name_bytes.len() };
    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), (*proc_ptr).image_file_name.as_mut_ptr(), copy_len);

    let thread_ptr = ExAllocatePoolWithTag(NonPagedPool, core::mem::size_of::<Thread>(), THREAD_TAG) as *mut Thread;
    if thread_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    setup.allocations[1] = (thread_ptr.cast(), THREAD_TAG);
    core::ptr::write_bytes(thread_ptr as *mut u8, 0, core::mem::size_of::<Thread>());

    let kstack_buf = ExAllocatePoolWithTag(NonPagedPool, KERNEL_STACK_SIZE, STACK_TAG);
    if kstack_buf.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    setup.allocations[2] = (kstack_buf, STACK_TAG);
    let kstack_top = (kstack_buf as usize + KERNEL_STACK_SIZE) & !0xF;

    (*thread_ptr).unique_thread_id = tid;
    (*thread_ptr).teb = teb_addr as *mut Teb;
    (*thread_ptr).process = proc_ptr;
    (*thread_ptr).user_stack_base = user_stack_base;
    (*thread_ptr).user_stack_limit = user_stack_top;

    let kthread = &mut (*thread_ptr).tcb;
    kthread.initial_stack = kstack_top as *mut core::ffi::c_void;
    kthread.stack_limit = kstack_buf as *mut core::ffi::c_void;
    kthread.state = ThreadState::Ready as u8;
    kthread.process = &raw mut (*proc_ptr).pcb;
    kthread.teb = teb_addr as *mut core::ffi::c_void;
    kthread.priority = 8;
    kthread.base_priority = 8;
    kthread.quantum = DEFAULT_QUANTUM;

    // 7. Format initial stack frame for KiSwapContext
    let ret_addr_slot = (kstack_top - 8) as *mut usize;
    *ret_addr_slot = ki_user_thread_start_trampoline as *const () as usize;

    let frame_base = kstack_top - 8 - 0x138;
    kthread.kernel_stack = frame_base as *mut core::ffi::c_void;

    let rbx_slot = (frame_base + 0x100) as *mut usize;
    *rbx_slot = loader_entry; // NTDLL binds the executable before entering its code.

    let rdi_slot = (frame_base + 0x108) as *mut usize;
    *rdi_slot = user_stack_top;      // RDI = user_stack_top (RSP)

    let rsi_slot = (frame_base + 0x110) as *mut usize;
    *rsi_slot = teb_addr;            // RSI = teb_addr (TEB)

    // 8. Register into scheduler queue
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
        "[PS] Process \"{}\" ready (PID: 0x{:X}, Initial Thread TID: 0x{:X}, Entry: 0x{:016X}, CR3: 0x{:X})",
        name,
        pid,
        tid,
        image_entry,
        cr3
    );

    core::mem::forget(setup);
    Ok((proc_ptr, kthread as *mut _))
}
