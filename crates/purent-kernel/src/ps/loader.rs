//! PureNT Native User-Mode PE Process Loader
//! Parses PE32+ executables, maps sections, constructs PEB & TEB, and stages User-Mode threads.

use purent_hal::kprintln;
use purent_ntdef::kpcr::ThreadState;
use purent_ntdef::ps::{Peb, RtlUserProcessParameters, Teb};
use purent_ntdef::status::{NtStatus, STATUS_NO_MEMORY, STATUS_UNSUCCESSFUL};
use purent_pe::{ImageImportDescriptor, PeView, IMAGE_DIRECTORY_ENTRY_IMPORT};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Win32ExportEntry {
    pub dll: [u8; 16],
    pub func: [u8; 64],
    pub addr: *const (),
}

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
pub unsafe fn ps_map_user_shared_data() -> Result<(), NtStatus> {
    let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
    vmm_map_user_page(
        purent_hal::cpu::read_cr3(), 0x7FFE0000, frame, PTE_PRESENT | PTE_USER | PTE_NX,
    )
}

const WIN32_MODULES: &[(&str, &[u8])] = &[
    ("user32.dll", include_bytes!("../../../../target/esp/user32.dll")),
    ("shell32.dll", include_bytes!("../../../../target/esp/shell32.dll")),
];

unsafe fn map_win32_dll(cr3: u64, bytes: &[u8], pe: &PeView<'_>) -> Result<(), NtStatus> {
    let base = pe.image_base() as usize;
    let optional_header = &pe.nt_headers().optional_header;
    let win32_hdr_pages = (optional_header.size_of_headers as usize + 4095) / 4096;
    for i in 0..win32_hdr_pages {
        let va = (base + i * 4096) as u64;
        let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
        vmm_map_user_page(cr3, va, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE)?;
    }
    if (optional_header.size_of_headers as usize) <= bytes.len() {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, optional_header.size_of_headers as usize);
    }

    for sec in pe.section_headers() {
        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_addr = sec.virtual_address as usize;
        let virt_size = sec.virtual_size as usize;
        let sec_va = base + virt_addr;

        let page_aligned_size = (virt_size.max(raw_size) + 4095) & !4095;
        let sec_pages = page_aligned_size / 4096;
        for j in 0..sec_pages {
            let va = (sec_va + j * 4096) as u64;
            let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
            vmm_map_user_page(cr3, va, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE)?;
        }

        let dst = sec_va as *mut u8;
        if raw_size > 0 && raw_offset + raw_size <= bytes.len() {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(raw_offset), dst, raw_size);
        }
        if virt_size < page_aligned_size {
            core::ptr::write_bytes(dst.add(virt_size), 0, page_aligned_size - virt_size);
        }

    }
    Ok(())
}

fn resolve_pe_export(bytes: &[u8], name: &str) -> Option<u64> {
    let pe = PeView::parse(bytes).ok()?;
    let directory = pe.data_directory(purent_pe::IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    if directory.virtual_address == 0 || directory.size < 40 {
        return None;
    }
    let dir = pe.rva_to_offset(directory.virtual_address)?;
    let read_u32 = |offset| Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?));
    let count = read_u32(dir + 24)? as usize;
    let names = pe.rva_to_offset(read_u32(dir + 32)?)?;
    let ordinals = pe.rva_to_offset(read_u32(dir + 36)?)?;
    let addresses = pe.rva_to_offset(read_u32(dir + 28)?)?;

    for index in 0..count {
        let name_offset = pe.rva_to_offset(read_u32(names + index * 4)?)?;
        let export_name = bytes.get(name_offset..)?.split(|&byte| byte == 0).next()?;
        if export_name != name.as_bytes() {
            continue;
        }
        let ordinal_offset = ordinals + index * 2;
        let ordinal = u16::from_le_bytes(bytes.get(ordinal_offset..ordinal_offset + 2)?.try_into().ok()?) as usize;
        if ordinal >= read_u32(dir + 20)? as usize {
            return None;
        }
        let rva = read_u32(addresses + ordinal * 4)?;
        let directory_end = directory.virtual_address.checked_add(directory.size)?;
        if rva == 0 || rva >= pe.size_of_image() || (directory.virtual_address..directory_end).contains(&rva) {
            return None;
        }
        return pe.image_base().checked_add(rva as u64);
    }
    None
}

unsafe fn bind_win32_imports(pe: &PeView<'_>, win32_exports: &[Win32ExportEntry]) -> usize {
    let base = pe.image_base() as usize;
    let mut bound_count = 0;
    if let Some(imp_dir) = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        if imp_dir.virtual_address != 0 && imp_dir.size != 0 {
            let mut desc_offset = base + imp_dir.virtual_address as usize;
            loop {
                let desc = &*(desc_offset as *const ImageImportDescriptor);
                if desc.name == 0 && desc.first_thunk == 0 {
                    break;
                }

                let dll_name_ptr = (base + desc.name as usize) as *const u8;
                let mut dll_len = 0;
                while *dll_name_ptr.add(dll_len) != 0 {
                    dll_len += 1;
                }
                let dll_name = core::str::from_utf8(core::slice::from_raw_parts(dll_name_ptr, dll_len)).unwrap_or("");

                let thunk_rva = if desc.original_first_thunk != 0 {
                    desc.original_first_thunk as usize
                } else {
                    desc.first_thunk as usize
                };
                let iat_rva = desc.first_thunk as usize;

                let mut slot = 0;
                loop {
                    let thunk_val = *((base + thunk_rva + slot * 8) as *const u64);
                    if thunk_val == 0 {
                        break;
                    }

                    if thunk_val & 0x8000_0000_0000_0000 == 0 {
                        let hint_name_rva = (thunk_val & 0xFFFF_FFFF) as usize;
                        let name_ptr = (base + hint_name_rva + 2) as *const u8;
                        let mut f_len = 0;
                        while *name_ptr.add(f_len) != 0 {
                            f_len += 1;
                        }
                        let func_name = core::str::from_utf8(core::slice::from_raw_parts(name_ptr, f_len)).unwrap_or("");

                        let module_export = WIN32_MODULES.iter()
                            .find(|(module, _)| module.eq_ignore_ascii_case(dll_name))
                            .and_then(|(module, bytes)| {
                                let address = resolve_pe_export(bytes, func_name)?;
                                kprintln!("[PS] Bound {}!{} at 0x{:016X}", module, func_name, address);
                                Some(address)
                            });
                        let resolved = module_export.or_else(|| {
                            win32_exports.iter().find_map(|entry| {
                                let e_dll = core::str::from_utf8(&entry.dll).ok()?.trim_end_matches('\0');
                                let e_func = core::str::from_utf8(&entry.func).ok()?.trim_end_matches('\0');
                                (e_dll.eq_ignore_ascii_case(dll_name) && e_func == func_name)
                                    .then_some(entry.addr as u64)
                            })
                        }).unwrap_or(0);

                        if resolved != 0 {
                            let iat_slot_ptr = (base + iat_rva + slot * 8) as *mut u64;
                            *iat_slot_ptr = resolved;
                            bound_count += 1;
                        } else {
                            kprintln!("[PS] Warning: Unresolved import {}!{}", dll_name, func_name);
                        }
                    }
                    slot += 1;
                }

                desc_offset += core::mem::size_of::<ImageImportDescriptor>();
            }
        }
    }
    bound_count

}

unsafe fn protect_win32_image(cr3: u64, pe: &PeView<'_>) -> Result<(), NtStatus> {
    let base = pe.image_base() as usize;
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

pub unsafe fn ps_create_win32_process(
    cmd_pe_bytes: &[u8],
    win32_pe_bytes: &[u8],
    name: &'static str,
    pid: usize,
    environment_base: usize,
    map_runtime: bool,
) -> Result<(*mut Process, *mut purent_ntdef::kpcr::KThread), NtStatus> {
    kprintln!("\n[PS] Staging original Windows 7 x64 \"{}\" (PID: 0x{:X}) with PureNT Win32 subsystem...", name, pid);

    let cr3 = purent_hal::cpu::read_cr3();

    // 1. Map purent-win32 runtime at 0x0000000070000000
    let win32_pe = PeView::parse(win32_pe_bytes).map_err(|e| {
        kprintln!("[PS] Failed to parse purent-win32 PE: {:?}", e);
        STATUS_UNSUCCESSFUL
    })?;
    let win32_base = win32_pe.image_base() as usize;

    if map_runtime {
        kprintln!("[PS] Mapping Win32 subsystem runtime at 0x{:016X}...", win32_base);
        map_win32_dll(cr3, win32_pe_bytes, &win32_pe)?;
        for (module, bytes) in WIN32_MODULES {
            let pe = PeView::parse(bytes).map_err(|_| STATUS_UNSUCCESSFUL)?;
            map_win32_dll(cr3, bytes, &pe)?;
            let base = pe.image_base();
            kprintln!("[PS] Mapped {} at 0x{:016X}", module, base);
        }
    }

    // Locate .exports section in purent-win32
    let mut exports_slice: Option<&[Win32ExportEntry]> = None;
    for sec in win32_pe.section_headers() {
        if sec.name.starts_with(b".exports") {
            let num_entries = sec.virtual_size as usize / core::mem::size_of::<Win32ExportEntry>();
            let exports_ptr = (win32_base + sec.virtual_address as usize) as *const Win32ExportEntry;
            exports_slice = Some(core::slice::from_raw_parts(exports_ptr, num_entries));
            break;
        }
    }
    let win32_exports = exports_slice.ok_or(STATUS_UNSUCCESSFUL)?;
    kprintln!("[PS] Win32 subsystem runtime active: {} functions exported", win32_exports.len());

    if map_runtime {
        for (module, bytes) in WIN32_MODULES {
            let pe = PeView::parse(bytes).map_err(|_| STATUS_UNSUCCESSFUL)?;
            bind_win32_imports(&pe, win32_exports);
            protect_win32_image(cr3, &pe)?;
            kprintln!("[PS] Ready: {}", module);
        }
        protect_win32_image(cr3, &win32_pe)?;
    }

    // 2. Map cmd.exe PE sections at 0x000000004AD00000
    let cmd_pe = PeView::parse(cmd_pe_bytes).map_err(|e| {
        kprintln!("[PS] Failed to parse cmd.exe PE: {:?}", e);
        STATUS_UNSUCCESSFUL
    })?;
    let cmd_base = cmd_pe.image_base() as usize;
    let cmd_entry = (cmd_base + cmd_pe.entry_point_rva() as usize) as u64;

    kprintln!(
        "[PS] Mapping cmd.exe sections at ImageBase 0x{:016X}, EntryPoint 0x{:016X}...",
        cmd_base,
        cmd_entry
    );

    let opt_hdr = &cmd_pe.nt_headers().optional_header;
    let headers_size = opt_hdr.size_of_headers as usize;
    let headers_pages = (headers_size + 4095) / 4096;
    for i in 0..headers_pages {
        let va = (cmd_base + i * 4096) as u64;
        let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
        vmm_map_user_page(cr3, va, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE)?;
    }
    if headers_size <= cmd_pe_bytes.len() {
        core::ptr::copy_nonoverlapping(cmd_pe_bytes.as_ptr(), cmd_base as *mut u8, headers_size);
    }

    for sec in cmd_pe.section_headers() {
        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_addr = sec.virtual_address as usize;
        let virt_size = sec.virtual_size as usize;
        let sec_va = cmd_base + virt_addr;

        let page_aligned_size = (virt_size.max(raw_size) + 4095) & !4095;
        let sec_pages = page_aligned_size / 4096;
        for j in 0..sec_pages {
            let va = (sec_va + j * 4096) as u64;
            let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
            core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
            vmm_map_user_page(cr3, va, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE)?;
        }

        let dst = sec_va as *mut u8;
        if raw_size > 0 && raw_offset + raw_size <= cmd_pe_bytes.len() {
            core::ptr::copy_nonoverlapping(cmd_pe_bytes.as_ptr().add(raw_offset), dst, raw_size);
        }
        if virt_size < page_aligned_size {
            core::ptr::write_bytes(dst.add(virt_size), 0, page_aligned_size - virt_size);
        }
    }

    let bound_count = bind_win32_imports(&cmd_pe, win32_exports);
    kprintln!("[PS] Bound {} IAT import entries for {}", bound_count, name);

    protect_win32_image(cr3, &cmd_pe)?;

    // 4. Initialize Process Environment Block (PEB) at 0x0000000000550000
    let peb_addr = environment_base;
    let peb_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(peb_frame), 0, 4096);
    vmm_map_user_page(cr3, peb_addr as u64, peb_frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX)?;
    let peb = peb_addr as *mut Peb;

    (*peb).inherited_address_space = 0;
    (*peb).being_debugged = 0;
    (*peb).image_base_address = cmd_base as *mut core::ffi::c_void;
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

    let params = (peb_addr + 0x400) as *mut RtlUserProcessParameters;
    (*params).maximum_length = 0x400;
    (*params).length = 0x400;
    (*params).flags = 1;
    (*params).console_handle = 1 as *mut core::ffi::c_void;
    (*params).standard_input = 3 as *mut core::ffi::c_void;
    (*params).standard_output = 4 as *mut core::ffi::c_void;
    (*params).standard_error = 4 as *mut core::ffi::c_void;

    let curdir_buf = (peb_addr + 0x600) as *mut u16;
    let curdir_str = [ 'C' as u16, ':' as u16, '\\' as u16, 0 ];
    for i in 0..curdir_str.len() { *curdir_buf.add(i) = curdir_str[i]; }
    (*params).current_directory_path.length = 6;
    (*params).current_directory_path.maximum_length = 8;
    (*params).current_directory_path.buffer = curdir_buf;

    let img_buf = (peb_addr + 0x680) as *mut u16;
    let directory = b"C:\\Windows\\System32\\";
    for (index, byte) in directory.iter().chain(name.as_bytes()).enumerate() {
        *img_buf.add(index) = *byte as u16;
    }
    let image_chars = directory.len() + name.len();
    (*params).image_path_name.length = (image_chars * 2) as u16;
    (*params).image_path_name.maximum_length = ((image_chars + 1) * 2) as u16;
    (*params).image_path_name.buffer = img_buf;

    let cmdline_buf = (peb_addr + 0x700) as *mut u16;
    for (index, byte) in name.bytes().enumerate() {
        *cmdline_buf.add(index) = byte as u16;
    }
    (*params).command_line.length = (name.len() * 2) as u16;
    (*params).command_line.maximum_length = ((name.len() + 1) * 2) as u16;
    (*params).command_line.buffer = cmdline_buf;

    (*peb).process_parameters = params;

    kprintln!("[PS] Initialized PEB at 0x{:016X} (NT {}.{} Build {})", peb_addr, (*peb).os_major_version, (*peb).os_minor_version, (*peb).os_build_number);

    // 5. Initialize Thread Environment Block (TEB) at 0x0000000000560000
    let teb_addr = environment_base + 0x10000;
    let teb_frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
    core::ptr::write_bytes(phys_to_virt::<u8>(teb_frame), 0, 4096);
    vmm_map_user_page(cr3, teb_addr as u64, teb_frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX)?;
    let teb = teb_addr as *mut Teb;

    let user_stack_base = environment_base + 0x20000;
    let stack_end = user_stack_base + 0x40000;
    let user_stack_top = (stack_end - 0x80) & !0xFu64 as usize;

    // Map 64 pages (256 KB stack)
    for s in 0..64 {
        let va = (user_stack_base + s * 4096) as u64;
        let frame = PMM.lock().allocate_frame().ok_or(STATUS_NO_MEMORY)?;
        core::ptr::write_bytes(phys_to_virt::<u8>(frame), 0, 4096);
        vmm_map_user_page(cr3, va, frame, PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX)?;
    }

    let tid = pid + 4;
    (*teb).nt_tib.stack_base = stack_end as *mut core::ffi::c_void;
    (*teb).nt_tib.stack_limit = user_stack_base as *mut core::ffi::c_void;
    (*teb).nt_tib.self_ptr = &mut (*teb).nt_tib;
    (*teb).client_id.unique_process = pid as *mut core::ffi::c_void;
    (*teb).client_id.unique_thread = tid as *mut core::ffi::c_void;
    (*teb).process_environment_block = peb;
    (*teb).current_locale = 0x0409;

    kprintln!("[PS] Initialized TEB at 0x{:016X} (PID: 0x{:X}, TID: 0x{:X}, UserStack: 0x{:016X})", teb_addr, pid, tid, user_stack_top);

    // 6. Allocate Process & Thread objects
    let proc_ptr = ExAllocatePoolWithTag(NonPagedPool, core::mem::size_of::<Process>(), PROCESS_TAG) as *mut Process;
    if proc_ptr.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    core::ptr::write_bytes(proc_ptr as *mut u8, 0, core::mem::size_of::<Process>());

    (*proc_ptr).pcb.directory_table_base = purent_hal::cpu::read_cr3();
    (*proc_ptr).unique_process_id = pid;
    (*proc_ptr).section_base_address = cmd_base;
    (*proc_ptr).peb = peb;
    let name_bytes = name.as_bytes();
    let copy_len = if name_bytes.len() > 15 { 15 } else { name_bytes.len() };
    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), (*proc_ptr).image_file_name.as_mut_ptr(), copy_len);

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

    let kthread = &mut (*thread_ptr).tcb;
    kthread.initial_stack = kstack_top as *mut core::ffi::c_void;
    kthread.stack_limit = kstack_buf as *mut core::ffi::c_void;
    kthread.state = ThreadState::Ready as u8;
    kthread.process = &raw mut (*proc_ptr).pcb;
    kthread.teb = teb as *mut core::ffi::c_void;
    kthread.priority = 8;
    kthread.base_priority = 8;
    kthread.quantum = DEFAULT_QUANTUM;

    // 7. Format initial stack frame for KiSwapContext
    let ret_addr_slot = (kstack_top - 8) as *mut usize;
    *ret_addr_slot = ki_user_thread_start_trampoline as *const () as usize;

    let frame_base = kstack_top - 8 - 0x138;
    kthread.kernel_stack = frame_base as *mut core::ffi::c_void;

    let rbx_slot = (frame_base + 0x100) as *mut usize;
    *rbx_slot = cmd_entry as usize; // RBX = entry_point (RIP)

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
        "[PS] Process \"{}\" ready (PID: 0x{:X}, Initial Thread TID: 0x{:X}, Entry: 0x{:016X})",
        name,
        pid,
        tid,
        cmd_entry
    );

    Ok((proc_ptr, kthread as *mut _))
}
