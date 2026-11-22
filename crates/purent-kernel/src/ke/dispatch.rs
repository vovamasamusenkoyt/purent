//! Central Windows NT System Call Dispatch Engine
//! Pure Rust dispatch: receives &mut TrapFrame, routes to Executive services, stores return status in frame.rax.

use purent_hal::kprintln;
use purent_ntdef::status::{NtStatus, STATUS_INVALID_HANDLE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use purent_ntdef::syscall::{
    TrapFrame, SYSCALL_PURENT_COMPOSE_RECEIVE, SYSCALL_PURENT_COMPOSE_FINISH, SYSCALL_PURENT_CONSOLE_INPUT, SYSCALL_PURENT_CONSOLE_EVENT,
    SYSCALL_PURENT_CONSOLE_SUBMIT, SYSCALL_PURENT_CONSOLE_OUTPUT, SYSCALL_PURENT_SHOW_DIALOG,
};
use crate::win32k::{self, input::{self, CONSOLE_INPUT}};
use purent_ntdef::{IoStatusBlock, ObjectAttributes};

use super::syscall::*;

#[no_mangle]
pub extern "win64" fn ki_system_call_dispatch(frame: &mut TrapFrame) {
    let syscall_nr = frame.rax;
    let a1 = frame.r10;
    let a2 = frame.rdx;
    let a3 = frame.r8;
    let a4 = frame.r9;

    if syscall_nr == SYSCALL_PURENT_CONSOLE_INPUT {
        frame.rax = if crate::ps::current_process_id() == Some(win32k::CONSOLE_CLIENT_PID) {
            CONSOLE_INPUT.wait_pop() as u64
        } else {
            purent_ntdef::status::STATUS_ACCESS_DENIED as u64
        };
        return;
    }
    if matches!(syscall_nr, SYSCALL_PURENT_CONSOLE_EVENT | SYSCALL_PURENT_CONSOLE_OUTPUT | SYSCALL_PURENT_CONSOLE_SUBMIT) {
        use purent_ntdef::status::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER};
        frame.rax = if crate::ps::current_process_id() != Some(win32k::CONHOST_PID) {
            STATUS_ACCESS_DENIED as u64
        } else {
            match syscall_nr {
                SYSCALL_PURENT_CONSOLE_EVENT => input::wait_host_event(),
                SYSCALL_PURENT_CONSOLE_OUTPUT => input::read_output_packet(),
                SYSCALL_PURENT_CONSOLE_SUBMIT if matches!(a1, 10 | 13 | 32..=126) => {
                    while !CONSOLE_INPUT.push(a1 as u8) {
                        unsafe { purent_hal::cpu::halt() };
                    }
                    STATUS_SUCCESS as u64
                }
                _ => STATUS_INVALID_PARAMETER as u64,
            }
        };
        return;
    }

    let status: NtStatus = match syscall_nr {
        SYSCALL_PURENT_COMPOSE_RECEIVE => win32k::compositor::receive(),
        SYSCALL_PURENT_COMPOSE_FINISH => win32k::compositor::finish(),
        SYSCALL_PURENT_SHOW_DIALOG => unsafe { crate::win32k::show_dialog(a1 as usize) },
        SYSCALL_NT_CREATE_FILE => unsafe {
            let file_handle = a1 as *mut usize;
            let desired_access = a2 as u32;
            let obj_attr = a3 as *mut ObjectAttributes;
            let io_status = a4 as *mut IoStatusBlock;

            let alloc_size: *mut i64 = frame.arg5();
            let file_attr: u32 = frame.arg6();
            let share_access: u32 = frame.arg7();
            let create_disp: u32 = frame.arg8();
            let create_opts: u32 = *(frame.rsp.wrapping_add(0x48) as *const u32);
            let ea_buf: *mut core::ffi::c_void = *(frame.rsp.wrapping_add(0x50) as *const u64) as *mut _;
            let ea_len: u32 = *(frame.rsp.wrapping_add(0x58) as *const u32);

            crate::zw::ZwCreateFile(
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
        },

        SYSCALL_NT_WRITE_FILE => unsafe {
            let file_handle = a1 as usize;
            let event = a2 as usize;
            let apc_routine = a3 as *mut core::ffi::c_void;
            let apc_context = a4 as *mut core::ffi::c_void;

            let io_status: *mut IoStatusBlock = frame.arg5();
            let buffer: *mut core::ffi::c_void = frame.arg6();
            let length: u32 = frame.arg7();
            let byte_offset: *mut i64 = frame.arg8();
            let key: *mut u32 = *(frame.rsp.wrapping_add(0x48) as *const u64) as *mut u32;

            crate::zw::ZwWriteFile(
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
        },

        SYSCALL_NT_READ_FILE => unsafe {
            let file_handle = a1 as usize;
            let event = a2 as usize;
            let apc_routine = a3 as *mut core::ffi::c_void;
            let apc_context = a4 as *mut core::ffi::c_void;

            let io_status: *mut IoStatusBlock = frame.arg5();
            let buffer: *mut core::ffi::c_void = frame.arg6();
            let length: u32 = frame.arg7();
            let byte_offset: *mut i64 = frame.arg8();
            let key: *mut u32 = *(frame.rsp.wrapping_add(0x48) as *const u64) as *mut u32;

            crate::zw::ZwReadFile(
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
        },

        SYSCALL_NT_CLOSE => {
            let handle = a1 as usize;
            let curr: *const u8 = unsafe { purent_hal::cpu::read_gs_u64(0x188) as *const u8 };
            let prev_mode: u8 = if !curr.is_null() {
                unsafe { *curr.add(0x1F6) }
            } else {
                1
            };
            let mode_str = if prev_mode == 1 { "UserMode (1)" } else { "KernelMode (0)" };
            if handle == 0 || handle > 0x1000 {
                kprintln!("[SYSCALL] NtClose(Handle=0x{:X}, PreviousMode={}) -> STATUS_INVALID_HANDLE (0xC0000008)", handle, mode_str);
                STATUS_INVALID_HANDLE
            } else {
                let st = unsafe { crate::zw::ZwClose(handle) };
                kprintln!("[SYSCALL] NtClose(Handle=0x{:X}, PreviousMode={}) -> Status: 0x{:08X}", handle, mode_str, st);
                st
            }
        }

        SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY => unsafe {
            let process_handle = a1 as usize;
            let base_address = a2 as *mut *mut core::ffi::c_void;
            let zero_bits = a3 as usize;
            let region_size = a4 as *mut usize;
            let allocation_type: u32 = frame.arg5();
            let protect: u32 = frame.arg6();

            let st = crate::mm::ZwAllocateVirtualMemory(
                process_handle,
                base_address,
                zero_bits,
                region_size,
                allocation_type,
                protect,
            );
            kprintln!(
                "[SYSCALL] NtAllocateVirtualMemory(Proc=0x{:X}, Base=0x{:p}, Size=0x{:X}, Type=0x{:X}, Prot=0x{:X}) -> 0x{:08X}",
                process_handle,
                if !base_address.is_null() { *base_address } else { core::ptr::null_mut() },
                if !region_size.is_null() { *region_size } else { 0 },
                allocation_type,
                protect,
                st
            );
            st
        },

        SYSCALL_NT_FREE_VIRTUAL_MEMORY => unsafe {
            let process_handle = a1 as usize;
            let base_address = a2 as *mut *mut core::ffi::c_void;
            let region_size = a3 as *mut usize;
            let free_type = a4 as u32;

            let st = crate::mm::ZwFreeVirtualMemory(
                process_handle,
                base_address,
                region_size,
                free_type,
            );
            kprintln!(
                "[SYSCALL] NtFreeVirtualMemory(Proc=0x{:X}, Base=0x{:p}, Size=0x{:X}, FreeType=0x{:X}) -> 0x{:08X}",
                process_handle,
                if !base_address.is_null() { *base_address } else { core::ptr::null_mut() },
                if !region_size.is_null() { *region_size } else { 0 },
                free_type,
                st
            );
            st
        },

        SYSCALL_NT_QUERY_VIRTUAL_MEMORY => unsafe {
            let process_handle = a1 as usize;
            let base_address = a2 as *mut core::ffi::c_void;
            let info_class = a3 as u32;
            let mem_info = a4 as *mut core::ffi::c_void;
            let mem_info_len: usize = frame.arg5();
            let return_len: *mut usize = frame.arg6();

            let st = crate::mm::ZwQueryVirtualMemory(
                process_handle,
                base_address,
                info_class,
                mem_info,
                mem_info_len,
                return_len,
            );
            kprintln!(
                "[SYSCALL] NtQueryVirtualMemory(Proc=0x{:X}, Base=0x{:p}, InfoClass=0x{:X}) -> 0x{:08X}",
                process_handle,
                base_address,
                info_class,
                st
            );
            st
        },

        SYSCALL_NT_PROTECT_VIRTUAL_MEMORY => unsafe {
            let process_handle = a1 as usize;
            let base_address = a2 as *mut *mut core::ffi::c_void;
            let region_size = a3 as *mut usize;
            let new_protect = a4 as u32;
            let old_protect: *mut u32 = frame.arg5();

            let st = crate::mm::ZwProtectVirtualMemory(
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            );
            kprintln!(
                "[SYSCALL] NtProtectVirtualMemory(Proc=0x{:X}, Base=0x{:p}, NewProt=0x{:X}) -> 0x{:08X}",
                process_handle,
                if !base_address.is_null() { *base_address } else { core::ptr::null_mut() },
                new_protect,
                st
            );
            st
        },

        SYSCALL_NT_CREATE_SECTION => unsafe {
            let section_handle = a1 as *mut usize;
            let desired_access = a2 as u32;
            let obj_attr = a3 as *mut ObjectAttributes;
            let max_size = a4 as *mut i64;
            let sec_protect: u32 = frame.arg5();
            let alloc_attr: u32 = frame.arg6();
            let file_handle: usize = frame.arg7();

            let st = crate::mm::ZwCreateSection(
                section_handle,
                desired_access,
                obj_attr,
                max_size,
                sec_protect,
                alloc_attr,
                file_handle,
            );
            kprintln!(
                "[SYSCALL] NtCreateSection(Handle=0x{:X}, Protect=0x{:X}, Attr=0x{:X}) -> 0x{:08X}",
                if !section_handle.is_null() { *section_handle } else { 0 },
                sec_protect,
                alloc_attr,
                st
            );
            st
        },

        SYSCALL_NT_MAP_VIEW_OF_SECTION => unsafe {
            let section_handle = a1 as usize;
            let process_handle = a2 as usize;
            let base_address = a3 as *mut *mut core::ffi::c_void;
            let zero_bits = a4 as usize;
            let commit_size: usize = frame.arg5();
            let section_offset: *mut i64 = frame.arg6();
            let view_size: *mut usize = frame.arg7();
            let inherit_disp: u32 = frame.arg8();
            let alloc_type: u32 = *(frame.rsp.wrapping_add(0x48) as *const u32);
            let win32_protect: u32 = *(frame.rsp.wrapping_add(0x50) as *const u32);

            let st = crate::mm::ZwMapViewOfSection(
                section_handle,
                process_handle,
                base_address,
                zero_bits,
                commit_size,
                section_offset,
                view_size,
                inherit_disp,
                alloc_type,
                win32_protect,
            );
            kprintln!(
                "[SYSCALL] NtMapViewOfSection(Sect=0x{:X}, Base=0x{:p}, Size=0x{:X}, Prot=0x{:X}) -> 0x{:08X}",
                section_handle,
                if !base_address.is_null() { *base_address } else { core::ptr::null_mut() },
                if !view_size.is_null() { *view_size } else { 0 },
                win32_protect,
                st
            );
            st
        },

        SYSCALL_NT_UNMAP_VIEW_OF_SECTION => unsafe {
            let process_handle = a1 as usize;
            let base_address = a2 as *mut core::ffi::c_void;
            let st = crate::mm::ZwUnmapViewOfSection(process_handle, base_address);
            kprintln!("[SYSCALL] NtUnmapViewOfSection(Proc=0x{:X}, Base=0x{:p}) -> 0x{:08X}", process_handle, base_address, st);
            st
        },

        SYSCALL_NT_YIELD_EXECUTION => {
            kprintln!("[SYSCALL] NtYieldExecution called from Ring 3 - yielding CPU quantum...");
            unsafe { crate::ke::ki_yield(); }
            kprintln!("[SYSCALL] NtYieldExecution: thread resumed, returning to Ring 3 via sysretq");
            STATUS_SUCCESS
        }

        SYSCALL_NT_TERMINATE_PROCESS => {
            kprintln!("[SYSCALL] NtTerminateProcess(Handle=0x{:X}, ExitStatus=0x{:08X}) - Process & Thread terminating!", a1, a2);
            unsafe {
                crate::ps::ps_terminate_current_thread(a2 as u32);
            }
        }

        _ => {
            kprintln!("[SYSCALL] Unknown Nt/Zw service 0x{:04X} (a1=0x{:X}, a2=0x{:X})", syscall_nr, a1, a2);
            STATUS_NOT_IMPLEMENTED
        }
    };

    frame.rax = status as u64;
}
