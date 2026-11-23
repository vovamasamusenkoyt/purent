//! Win32 front end for the built-in executable catalog.

use purent_ntdef::builtin_exec::{child_handle, EXECUTABLES, SYSTEM_DIRECTORY};
use purent_ntdef::status::{
    STATUS_CONFLICTING_ADDRESSES, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND,
};
use purent_ntdef::syscall::{
    nt_syscall1, SYSCALL_PURENT_OPEN_BUILTIN, SYSCALL_PURENT_START_BUILTIN,
};

#[repr(C)]
struct ProcessInformation {
    process: usize,
    thread: usize,
    process_id: u32,
    thread_id: u32,
}

const FILE_NOT_FOUND: u32 = 2;
const INVALID_PARAMETER: u32 = 87;

pub fn matches(wide: &[u16], ascii: &[u8]) -> bool {
    wide.len() == ascii.len()
        && wide.iter().zip(ascii).all(|(&unit, &byte)| {
            u8::try_from(unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(&byte))
        })
}

pub unsafe fn wide_string<'a>(ptr: *const u16) -> Option<&'a [u16]> {
    if ptr.is_null() {
        return None;
    }
    for index in 0..32767 {
        if *ptr.add(index) == 0 {
            return Some(core::slice::from_raw_parts(ptr, index));
        }
    }
    None
}

fn first_argument(command: &[u16]) -> Option<&[u16]> {
    let is_space = |unit| matches!(unit, 9 | 32);
    let start = command.iter().position(|&unit| !is_space(unit))?;
    let command = &command[start..];
    if command[0] == b'"' as u16 {
        let tail = &command[1..];
        let end = tail.iter().position(|&unit| unit == b'"' as u16)?;
        return Some(&tail[..end]);
    }
    let end = command
        .iter()
        .position(|&unit| is_space(unit))
        .unwrap_or(command.len());
    Some(&command[..end])
}

pub unsafe fn lookup(name: &[u16], append_exe: bool) -> Option<(usize, &'static str, u32)> {
    lookup_pattern(name, append_exe, false)
}

pub unsafe fn lookup_pattern(
    name: &[u16],
    append_exe: bool,
    find: bool,
) -> Option<(usize, &'static str, u32)> {
    let file = match name.get(..SYSTEM_DIRECTORY.len()) {
        Some(prefix) if matches(prefix, SYSTEM_DIRECTORY) => &name[SYSTEM_DIRECTORY.len()..],
        _ => name,
    };
    let (file, stem) = if find && file.ends_with(&[b'.' as u16, b'*' as u16]) {
        (&file[..file.len() - 2], true)
    } else {
        (file, append_exe)
    };
    EXECUTABLES
        .iter()
        .copied()
        .enumerate()
        .find_map(|(index, candidate)| {
            let text = candidate.as_bytes();
            if !matches(file, text) && !(stem && matches(file, &text[..text.len() - 4])) {
                return None;
            }
            let size = nt_syscall1(SYSCALL_PURENT_OPEN_BUILTIN, index as u64);
            (size > 0).then_some((index, candidate, size as u32))
        })
}

pub unsafe fn attributes(name: &[u16]) -> Option<(u32, u32)> {
    if [
        b"C:\\".as_slice(),
        b"C:\\Windows",
        b"C:\\Windows\\System32",
        SYSTEM_DIRECTORY,
    ]
    .iter()
    .any(|directory| matches(name, directory))
    {
        return Some((0x10, 0));
    }
    lookup(name, false).map(|(_, _, size)| (0x80, size))
}

pub unsafe fn create(app: *const u16, command: *const u16, info: *mut core::ffi::c_void) -> i32 {
    if info.is_null() {
        crate::kernel32::LAST_ERROR = INVALID_PARAMETER;
        return 0;
    }
    let name = if app.is_null() {
        wide_string(command).and_then(first_argument)
    } else {
        wide_string(app)
    };

    let Some((index, _, _)) = name.and_then(|name| lookup(name, app.is_null())) else {
        crate::kernel32::LAST_ERROR = FILE_NOT_FOUND;
        return 0;
    };
    let status = nt_syscall1(SYSCALL_PURENT_START_BUILTIN, index as u64);
    if status <= 0 {
        crate::kernel32::LAST_ERROR = match status {
            STATUS_OBJECT_NAME_NOT_FOUND => FILE_NOT_FOUND,
            STATUS_NO_MEMORY => 8,
            STATUS_CONFLICTING_ADDRESSES => 170, // ERROR_BUSY
            _ => INVALID_PARAMETER,
        };
        return 0;
    }

    let pid = status as usize;
    info.cast::<ProcessInformation>().write(ProcessInformation {
        process: child_handle(pid, false),
        thread: child_handle(pid, true),
        process_id: pid as u32,
        thread_id: (pid + 4) as u32,
    });
    1
}

pub unsafe fn search(
    file: *const u16,
    ext: *const u16,
    capacity: u32,
    buffer: *mut u16,
    part: *mut *mut u16,
) -> u32 {
    if !part.is_null() {
        *part = core::ptr::null_mut();
    }
    let append = wide_string(ext).is_some_and(|ext| matches(ext, b".exe"));
    let Some((_, file, _)) = wide_string(file).and_then(|name| lookup(name, append)) else {
        crate::kernel32::LAST_ERROR = FILE_NOT_FOUND;
        return 0;
    };
    let len = SYSTEM_DIRECTORY.len() + file.len();
    if buffer.is_null() || capacity as usize <= len {
        return (len + 1) as u32;
    }
    for (index, &byte) in SYSTEM_DIRECTORY.iter().chain(file.as_bytes()).enumerate() {
        *buffer.add(index) = byte as u16;
    }
    *buffer.add(len) = 0;
    if !part.is_null() {
        *part = buffer.add(SYSTEM_DIRECTORY.len());
    }
    len as u32
}
