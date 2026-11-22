//! PureNT Clean-Room Win32 Kernel32 Subsystem (KERNEL32.dll)
//! Reverse-engineered implementation for Windows 7 SP1 x64 cmd.exe execution

use purent_ntdef::syscall::{
    nt_current_peb_address, nt_syscall0, nt_syscall1, nt_syscall2, nt_syscall4,
    nt_syscall6, nt_syscall7, SYSCALL_PURENT_CONSOLE_INPUT,
};

pub static mut LAST_ERROR: u32 = 0;

// Standard Handle Constants
pub const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;  // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;  // -12

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Coord {
    pub x: i16,
    pub y: i16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SmallRect {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ConsoleScreenBufferInfo {
    pub size: Coord,
    pub cursor_position: Coord,
    pub attributes: u16,
    pub window: SmallRect,
    pub maximum_window_size: Coord,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CPInfo {
    pub max_char_size: u32,
    pub default_char: [u8; 2],
    pub lead_byte: [u8; 12],
}

#[repr(C)]
pub struct CriticalSection {
    pub debug_info: *mut core::ffi::c_void,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: usize,
    pub lock_semaphore: usize,
    pub spin_count: usize,
}

#[no_mangle]
pub unsafe extern "win64" fn GetLastError() -> u32 {
    LAST_ERROR
}

#[no_mangle]
pub unsafe extern "win64" fn SetLastError(err: u32) {
    LAST_ERROR = err;
}

#[no_mangle]
pub unsafe extern "win64" fn GetCurrentThreadId() -> u32 {
    let teb = purent_ntdef::syscall::nt_current_teb_address();
    *(teb.wrapping_add(0x48) as *const u32)
}

#[no_mangle]
pub unsafe extern "win64" fn GetCurrentProcessId() -> u32 {
    let teb = purent_ntdef::syscall::nt_current_teb_address();
    *(teb.wrapping_add(0x40) as *const u32)
}

#[no_mangle]
pub unsafe extern "win64" fn GetCurrentProcess() -> usize {
    !0usize // (HANDLE)-1
}

#[no_mangle]
pub unsafe extern "win64" fn OpenThread(_access: u32, _inherit: i32, _tid: u32) -> usize {
    0x10 // Valid pseudo thread handle
}

#[no_mangle]
pub unsafe extern "win64" fn GetStdHandle(std_handle: u32) -> usize {
    match std_handle {
        STD_INPUT_HANDLE => 0x03,
        STD_OUTPUT_HANDLE => 0x04,
        STD_ERROR_HANDLE => 0x04,
        _ => 0x04,
    }
}

#[no_mangle]
pub unsafe extern "win64" fn WriteFile(
    file: usize,
    buffer: *const core::ffi::c_void,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: *mut u32,
    _overlapped: usize,
) -> i32 {
    if buffer.is_null() {
        return 0;
    }
    let mut io_status = [0usize; 2];
    let st = nt_syscall7(
        0x05, // NtWriteFile
        file as u64,
        0,
        0,
        0,
        io_status.as_mut_ptr() as u64,
        buffer as u64,
        number_of_bytes_to_write as u64,
    );
    // Stack arguments 7, 8, 9 passed if full NT call, but our dispatch handles it
    if !number_of_bytes_written.is_null() {
        *number_of_bytes_written = number_of_bytes_to_write;
    }
    if st >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn WriteConsoleW(
    console_output: usize,
    buffer: *const u16,
    number_of_chars_to_write: u32,
    number_of_chars_written: *mut u32,
    _reserved: usize,
) -> i32 {
    if buffer.is_null() {
        return 0;
    }
    // Convert UTF-16 characters to UTF-8 on the fly and write via NtWriteFile
    let mut utf8_buf = [0u8; 128];
    let mut i = 0;
    while i < number_of_chars_to_write as usize {
        let mut chunk_idx = 0;
        while i < number_of_chars_to_write as usize && chunk_idx < 126 {
            let ch = *buffer.add(i);
            if ch < 128 {
                utf8_buf[chunk_idx] = ch as u8;
                chunk_idx += 1;
            } else {
                utf8_buf[chunk_idx] = b'?';
                chunk_idx += 1;
            }
            i += 1;
        }
        let mut written: u32 = 0;
        WriteFile(console_output, utf8_buf.as_ptr() as *const _, chunk_idx as u32, &mut written, 0);
    }
    if !number_of_chars_written.is_null() {
        *number_of_chars_written = number_of_chars_to_write;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn ReadFile(
    file: usize,
    buffer: *mut core::ffi::c_void,
    number_of_bytes_to_read: u32,
    number_of_bytes_read: *mut u32,
    _overlapped: usize,
) -> i32 {
    if buffer.is_null() {
        return 0;
    }
    let mut io_status = [0usize; 2];
    let st = nt_syscall7(
        0x03, // NtReadFile
        file as u64,
        0,
        0,
        0,
        io_status.as_mut_ptr() as u64,
        buffer as u64,
        number_of_bytes_to_read as u64,
    );
    if !number_of_bytes_read.is_null() {
        *number_of_bytes_read = number_of_bytes_to_read;
    }
    if st >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn ReadConsoleW(
    console_input: usize,
    buffer: *mut u16,
    number_of_chars_to_read: u32,
    number_of_chars_read: *mut u32,
    _input_control: usize,
) -> i32 {
    if !number_of_chars_read.is_null() {
        *number_of_chars_read = 0;
    }
    if buffer.is_null() || console_input != GetStdHandle(STD_INPUT_HANDLE) {
        return 0;
    }
    let capacity = number_of_chars_to_read as usize;
    let mut len = 0;
    while len < capacity {
        let ch = nt_syscall0(SYSCALL_PURENT_CONSOLE_INPUT);
        if ch < 0 {
            return 0;
        }
        *buffer.add(len) = ch as u16;
        len += 1;
        if ch == 10 {
            break;
        }
    }
    if !number_of_chars_read.is_null() {
        *number_of_chars_read = len as u32;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetConsoleMode(_handle: usize, mode: *mut u32) -> i32 {
    if !mode.is_null() {
        *mode = 0x0007; // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleMode(_handle: usize, _mode: u32) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetConsoleScreenBufferInfo(
    _console: usize,
    info: *mut ConsoleScreenBufferInfo,
) -> i32 {
    if info.is_null() { return 0; }
    (*info).size = Coord { x: 80, y: 25 };
    (*info).cursor_position = Coord { x: 0, y: 0 };
    (*info).attributes = 0x07; // Light gray on black
    (*info).window = SmallRect { left: 0, top: 0, right: 79, bottom: 24 };
    (*info).maximum_window_size = Coord { x: 80, y: 25 };
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetConsoleOutputCP() -> u32 {
    437 // United States OEM code page
}

#[no_mangle]
pub unsafe extern "win64" fn GetACP() -> u32 {
    1252 // Windows-1252 ANSI
}

#[no_mangle]
pub unsafe extern "win64" fn GetCPInfo(_code_page: u32, info: *mut CPInfo) -> i32 {
    if info.is_null() { return 0; }
    (*info).max_char_size = 1;
    (*info).default_char = [b'?' , 0];
    1
}

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleTextAttribute(_console: usize, _attr: u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleCursorPosition(_console: usize, _pos: Coord) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn FillConsoleOutputCharacterW(
    _console: usize,
    _char: u16,
    length: u32,
    _coord: Coord,
    written: *mut u32,
) -> i32 {
    if !written.is_null() { *written = length; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn FillConsoleOutputAttribute(
    _console: usize,
    _attr: u16,
    length: u32,
    _coord: Coord,
    written: *mut u32,
) -> i32 {
    if !written.is_null() { *written = length; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn ScrollConsoleScreenBufferW(
    _console: usize,
    _scroll_rect: *const SmallRect,
    _clip_rect: *const SmallRect,
    _dest_origin: Coord,
    _fill: *const core::ffi::c_void,
) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn FlushConsoleInputBuffer(_console: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn FlushFileBuffers(_file: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetCommandLineW() -> *const u16 {
    static CMDLINE: [u16; 8] = [
        'c' as u16, 'm' as u16, 'd' as u16, '.' as u16, 'e' as u16, 'x' as u16, 'e' as u16, 0,
    ];
    CMDLINE.as_ptr()
}

#[no_mangle]
pub unsafe extern "win64" fn GetEnvironmentVariableW(
    _name: *const u16,
    _buffer: *mut u16,
    _size: u32,
) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "win64" fn SetEnvironmentVariableW(_name: *const u16, _value: *const u16) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetEnvironmentStringsW() -> *const u16 {
    static ENV_STRINGS: [u16; 16] = [
        'P' as u16, 'A' as u16, 'T' as u16, 'H' as u16, '=' as u16, 'C' as u16, ':' as u16,
        '\\' as u16, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    ENV_STRINGS.as_ptr()
}

#[no_mangle]
pub unsafe extern "win64" fn FreeEnvironmentStringsW(_env: *const u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetCurrentDirectoryW(buffer_len: u32, buffer: *mut u16) -> u32 {
    static CUR_DIR: [u16; 4] = ['C' as u16, ':' as u16, '\\' as u16, 0];
    if buffer.is_null() || buffer_len < 4 { return 4; }
    for i in 0..4 { *buffer.add(i) = CUR_DIR[i]; }
    3
}

#[no_mangle]
pub unsafe extern "win64" fn SetCurrentDirectoryW(_path: *const u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    static WIN_DIR: [u16; 11] = [
        'C' as u16, ':' as u16, '\\' as u16, 'W' as u16, 'i' as u16, 'n' as u16, 'd' as u16,
        'o' as u16, 'w' as u16, 's' as u16, 0,
    ];
    if buffer.is_null() || size < 11 { return 11; }
    for i in 0..11 { *buffer.add(i) = WIN_DIR[i]; }
    10
}

#[no_mangle]
pub unsafe extern "win64" fn GetVolumePathNameW(_path: *const u16, volume_path_name: *mut u16, buffer_length: u32) -> i32 {
    GetCurrentDirectoryW(buffer_length, volume_path_name);
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetFullPathNameW(
    filename: *const u16,
    buffer_len: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    if filename.is_null() || buffer.is_null() { return 0; }
    let mut i = 0;
    while i < buffer_len as usize - 1 && *filename.add(i) != 0 {
        *buffer.add(i) = *filename.add(i);
        i += 1;
    }
    *buffer.add(i) = 0;
    if !file_part.is_null() { *file_part = buffer; }
    i as u32
}

#[no_mangle]
pub unsafe extern "win64" fn GetVolumeInformationW(
    _root_path: *const u16,
    volume_name_buf: *mut u16,
    vol_size: u32,
    serial_num: *mut u32,
    max_component_len: *mut u32,
    fs_flags: *mut u32,
    fs_name_buf: *mut u16,
    fs_name_size: u32,
) -> i32 {
    if !volume_name_buf.is_null() && vol_size > 0 { *volume_name_buf = 0; }
    if !serial_num.is_null() { *serial_num = 0x1337BEEF; }
    if !max_component_len.is_null() { *max_component_len = 255; }
    if !fs_flags.is_null() { *fs_flags = 3; }
    if !fs_name_buf.is_null() && fs_name_size >= 5 {
        let ntfs = ['N' as u16, 'T' as u16, 'F' as u16, 'S' as u16, 0];
        for i in 0..5 { *fs_name_buf.add(i) = ntfs[i]; }
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetDiskFreeSpaceExW(
    _dir: *const u16,
    free_bytes: *mut u64,
    total_bytes: *mut u64,
    total_free: *mut u64,
) -> i32 {
    if !free_bytes.is_null() { *free_bytes = 100 * 1024 * 1024 * 1024; }
    if !total_bytes.is_null() { *total_bytes = 500 * 1024 * 1024 * 1024; }
    if !total_free.is_null() { *total_free = 100 * 1024 * 1024 * 1024; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetDriveTypeW(_root: *const u16) -> u32 {
    3 // DRIVE_FIXED
}

#[no_mangle]
pub unsafe extern "win64" fn GetFileType(_file: usize) -> u32 {
    2 // FILE_TYPE_CHAR (console)
}

#[no_mangle]
pub unsafe extern "win64" fn Sleep(ms: u32) {
    if ms > 0 {
        nt_syscall0(0x43); // NtYieldExecution
    }
}

#[no_mangle]
pub unsafe extern "win64" fn TerminateProcess(_proc: usize, exit_code: u32) -> i32 {
    nt_syscall2(0x29, !0u64, exit_code as u64);
    1
}

#[no_mangle]
pub unsafe extern "win64" fn WaitForSingleObject(_handle: usize, _ms: u32) -> u32 {
    0 // WAIT_OBJECT_0
}

#[no_mangle]
pub unsafe extern "win64" fn CloseHandle(handle: usize) -> i32 {
    let st = nt_syscall1(0x0C, handle as u64); // NtClose
    if st >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn GetProcessHeap() -> usize {
    let peb = nt_current_peb_address();
    *(peb.wrapping_add(0x30) as *const usize) // PEB.ProcessHeap
}

#[no_mangle]
pub unsafe extern "win64" fn HeapAlloc(_heap: usize, _flags: u32, size: usize) -> *mut core::ffi::c_void {
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size = (size + 4095) & !4095;
    let st = nt_syscall6(
        0x15, // NtAllocateVirtualMemory
        0,
        &mut base as *mut _ as u64,
        0,
        &mut region_size as *mut _ as u64,
        0x3000,
        0x04,
    );
    if st == 0 { base } else { core::ptr::null_mut() }
}

#[no_mangle]
pub unsafe extern "win64" fn HeapFree(_heap: usize, _flags: u32, _mem: *mut core::ffi::c_void) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "win64" fn HeapReAlloc(
    heap: usize,
    flags: u32,
    mem: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    if mem.is_null() {
        return HeapAlloc(heap, flags, size);
    }
    mem
}

#[no_mangle]
pub unsafe extern "win64" fn HeapSize(_heap: usize, _flags: u32, _mem: *const core::ffi::c_void) -> usize {
    4096
}

#[no_mangle]
pub unsafe extern "win64" fn HeapSetInformation(
    _heap: usize,
    _info_class: u32,
    _info: *mut core::ffi::c_void,
    _len: usize,
) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "win64" fn VirtualAlloc(
    addr: *mut core::ffi::c_void,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut core::ffi::c_void {
    let mut base = addr;
    let mut region_size = size;
    let st = nt_syscall6(0x15, 0, &mut base as *mut _ as u64, 0, &mut region_size as *mut _ as u64, alloc_type as u64, protect as u64);
    if st == 0 { base } else { core::ptr::null_mut() }
}

#[no_mangle]
pub unsafe extern "win64" fn VirtualFree(addr: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32 {
    let mut base = addr;
    let mut region_size = size;
    let st = nt_syscall4(0x1B, 0, &mut base as *mut _ as u64, &mut region_size as *mut _ as u64, free_type as u64);
    if st == 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn VirtualQuery(
    addr: *const core::ffi::c_void,
    buffer: *mut core::ffi::c_void,
    len: usize,
) -> usize {
    let mut ret_len = 0usize;
    let st = nt_syscall6(0x20, 0, addr as u64, 0, buffer as u64, len as u64, &mut ret_len as *mut _ as u64);
    if st == 0 { ret_len } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn GlobalAlloc(_flags: u32, size: usize) -> *mut core::ffi::c_void {
    HeapAlloc(0, 0, size)
}

#[no_mangle]
pub unsafe extern "win64" fn GlobalFree(ptr: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    HeapFree(0, 0, ptr);
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "win64" fn LocalFree(ptr: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    GlobalFree(ptr)
}

#[no_mangle]
pub unsafe extern "win64" fn InitializeCriticalSection(cs: *mut CriticalSection) {
    if !cs.is_null() {
        core::ptr::write_bytes(cs as *mut u8, 0, core::mem::size_of::<CriticalSection>());
    }
}

#[no_mangle]
pub unsafe extern "win64" fn EnterCriticalSection(_cs: *mut CriticalSection) {}

#[no_mangle]
pub unsafe extern "win64" fn LeaveCriticalSection(_cs: *mut CriticalSection) {}

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleCtrlHandler(_handler: usize, _add: i32) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn SetUnhandledExceptionFilter(_filter: usize) -> usize { 0 }

#[no_mangle]
pub unsafe extern "win64" fn UnhandledExceptionFilter(_info: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetModuleHandleW(_module_name: *const u16) -> usize {
    (*(nt_current_peb_address() as *const purent_ntdef::ps::Peb)).image_base_address as usize
}

#[no_mangle]
pub unsafe extern "win64" fn GetModuleFileNameW(
    _module: usize,
    filename: *mut u16,
    size: u32,
) -> u32 {
    static CMD_PATH: [u16; 28] = [
        'C' as u16, ':' as u16, '\\' as u16, 'W' as u16, 'i' as u16, 'n' as u16, 'd' as u16,
        'o' as u16, 'w' as u16, 's' as u16, '\\' as u16, 'S' as u16, 'y' as u16, 's' as u16,
        't' as u16, 'e' as u16, 'm' as u16, '3' as u16, '2' as u16, '\\' as u16, 'c' as u16,
        'm' as u16, 'd' as u16, '.' as u16, 'e' as u16, 'x' as u16, 'e' as u16, 0,
    ];
    if filename.is_null() || size < 28 { return 28; }
    for i in 0..28 { *filename.add(i) = CMD_PATH[i]; }
    27
}

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleInputExeNameW(_name: *const u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn IsDebuggerPresent() -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn CopyFileExW(_from: *const u16, _to: *const u16, _progress: *mut core::ffi::c_void, _data: *mut core::ffi::c_void, _cancel: *mut i32, _flags: u32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn SetThreadUILanguage(_lang: u16) -> u16 { 0x0409 }

#[no_mangle]
pub unsafe extern "win64" fn GetProcAddress(_module: usize, proc_name: *const u8) -> usize {
    if !proc_name.is_null() {
        let mut len = 0;
        while *proc_name.add(len) != 0 { len += 1; }
        let name = core::str::from_utf8(core::slice::from_raw_parts(proc_name, len)).unwrap_or("");
        if name == "CopyFileExW" { return CopyFileExW as *const () as usize; }
        if name == "IsDebuggerPresent" { return IsDebuggerPresent as *const () as usize; }
        if name == "SetConsoleInputExeNameW" { return SetConsoleInputExeNameW as *const () as usize; }
        if name == "SetThreadUILanguage" { return SetThreadUILanguage as *const () as usize; }
        if let Some(addr) = crate::resolve_win32_symbol("kernel32.dll", name) {
            return addr;
        }
        if let Some(addr) = crate::resolve_win32_symbol("ntdll.dll", name) {
            return addr;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "win64" fn LoadLibraryW(_lib_name: *const u16) -> usize { 0 }

#[no_mangle]
pub unsafe extern "win64" fn LoadLibraryExA(_lib_name: *const u8, _file: usize, _flags: u32) -> usize { 0 }

#[no_mangle]
pub unsafe extern "win64" fn FreeLibrary(_module: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn DelayLoadFailureHook(_dll: *const u8, _proc: *const u8) -> usize { 0 }

// Registry stubs: return ERROR_FILE_NOT_FOUND (2) so cmd operates with default settings
#[no_mangle]
pub unsafe extern "win64" fn RegOpenKeyExW(
    _hkey: usize,
    _sub_key: *const u16,
    _options: u32,
    _sam: u32,
    res_key: *mut usize,
) -> i32 {
    if !res_key.is_null() { *res_key = 0; }
    2 // ERROR_FILE_NOT_FOUND
}

#[no_mangle]
pub unsafe extern "win64" fn RegQueryValueExW(
    _hkey: usize,
    _value_name: *const u16,
    _reserved: *mut u32,
    _type: *mut u32,
    _data: *mut u8,
    _cb_data: *mut u32,
) -> i32 {
    2 // ERROR_FILE_NOT_FOUND
}

#[no_mangle]
pub unsafe extern "win64" fn RegCloseKey(_hkey: usize) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn RegCreateKeyExW(
    _hkey: usize, _sub_key: *const u16, _reserved: u32, _class: *mut u16,
    _options: u32, _sam: u32, _security: usize, result: *mut usize, _disposition: *mut u32,
) -> i32 {
    if !result.is_null() { *result = 0; }
    2
}

#[no_mangle]
pub unsafe extern "win64" fn RegSetValueExW(
    _hkey: usize, _value_name: *const u16, _reserved: u32, _type: u32, _data: *const u8, _cb_data: u32,
) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn RegDeleteValueW(_hkey: usize, _value_name: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn RegDeleteKeyExW(_hkey: usize, _sub_key: *const u16, _sam: u32, _reserved: u32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn GetVersion() -> u32 {
    // 0x1DB10106 (Windows 7 SP1 build 7601)
    0x1DB10106
}

#[no_mangle]
pub unsafe extern "win64" fn GetTickCount() -> u32 { 1000 }

#[no_mangle]
pub unsafe extern "win64" fn QueryPerformanceCounter(count: *mut i64) -> i32 {
    if !count.is_null() { *count = 1000000; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetTimeFormatW(
    _locale: u32, _flags: u32, _time: usize, _format: *const u16,
    timestr: *mut u16, count: i32,
) -> i32 {
    static TIME: [u16; 9] = ['1' as u16, '2' as u16, ':' as u16, '0' as u16, '0' as u16, ':' as u16, '0' as u16, '0' as u16, 0];
    if timestr.is_null() || count < 9 { return 9; }
    for i in 0..9 { *timestr.add(i) = TIME[i]; }
    9
}

#[no_mangle]
pub unsafe extern "win64" fn GetDateFormatW(
    _locale: u32, _flags: u32, _date: usize, _format: *const u16,
    datestr: *mut u16, count: i32,
) -> i32 {
    static DATE: [u16; 11] = ['2' as u16, '0' as u16, '2' as u16, '6' as u16, '-' as u16, '1' as u16, '1' as u16, '-' as u16, '2' as u16, '2' as u16, 0];
    if datestr.is_null() || count < 11 { return 11; }
    for i in 0..11 { *datestr.add(i) = DATE[i]; }
    11
}

#[no_mangle]
pub unsafe extern "win64" fn GetSystemTimeAsFileTime(filetime: *mut u64) {
    if !filetime.is_null() { *filetime = 133000000000000000; }
}

#[no_mangle]
pub unsafe extern "win64" fn GetUserDefaultLCID() -> u32 { 0x0409 }

#[no_mangle]
pub unsafe extern "win64" fn GetThreadLocale() -> u32 { 0x0409 }

#[no_mangle]
pub unsafe extern "win64" fn SetThreadLocale(_locale: u32) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetLocaleInfoW(
    _locale: u32, _lc_type: u32, lc_data: *mut u16, count: i32,
) -> i32 {
    if !lc_data.is_null() && count > 0 { *lc_data = 0; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn FormatMessageW(
    flags: u32,
    _source: usize,
    msg_id: u32,
    _lang_id: u32,
    buffer: *mut u16,
    size: u32,
    args: usize,
) -> u32 {
    let template: &[u16] = match msg_id {
        9040 => {
            // "Microsoft Windows [Version %1]"
            &[
                'M' as u16, 'i' as u16, 'c' as u16, 'r' as u16, 'o' as u16, 's' as u16, 'o' as u16, 'f' as u16, 't' as u16, ' ' as u16,
                'W' as u16, 'i' as u16, 'n' as u16, 'd' as u16, 'o' as u16, 'w' as u16, 's' as u16, ' ' as u16,
                '[' as u16, 'V' as u16, 'e' as u16, 'r' as u16, 's' as u16, 'i' as u16, 'o' as u16, 'n' as u16, ' ' as u16,
                '%' as u16, '1' as u16, ']' as u16, 0,
            ]
        }
        _ => return 0,
    };

    let mut out_buf = buffer;
    let mut out_capacity = size as usize;

    if (flags & 0x0100) != 0 {
        let heap = GetProcessHeap();
        let allocated = HeapAlloc(heap, 0, 4096) as *mut u16;
        if allocated.is_null() { return 0; }
        *(buffer as *mut *mut u16) = allocated;
        out_buf = allocated;
        out_capacity = 2048;
    }

    if out_buf.is_null() || out_capacity == 0 {
        return 0;
    }

    let ignore_inserts = (flags & 0x0200) != 0;
    let arg_list: *const *const u16 = if (flags & 0x2000) != 0 {
        args as *const *const u16
    } else if args != 0 {
        *(args as *const *const *const u16)
    } else {
        core::ptr::null()
    };
    let mut in_idx = 0;
    let mut out_idx = 0;

    while in_idx < template.len() && template[in_idx] != 0 && out_idx + 1 < out_capacity {
        let ch = template[in_idx];
        if !ignore_inserts && ch == '%' as u16 && in_idx + 1 < template.len() {
            let next_ch = template[in_idx + 1];
            if next_ch >= '1' as u16 && next_ch <= '9' as u16 {
                let arg_idx = (next_ch - '1' as u16) as usize;
                in_idx += 2;
                if !arg_list.is_null() {
                    let insert_str = *arg_list.add(arg_idx);
                    if !insert_str.is_null() {
                        let mut s = 0;
                        while *insert_str.add(s) != 0 && out_idx + 1 < out_capacity {
                            *out_buf.add(out_idx) = *insert_str.add(s);
                            out_idx += 1;
                            s += 1;
                        }
                    }
                }
                continue;
            }
        }
        *out_buf.add(out_idx) = ch;
        out_idx += 1;
        in_idx += 1;
    }
    *out_buf.add(out_idx) = 0;
    out_idx as u32
}

#[no_mangle]
pub unsafe extern "win64" fn MultiByteToWideChar(
    _cp: u32, _flags: u32, mb: *const u8, mb_len: i32,
    wc: *mut u16, wc_len: i32,
) -> i32 {
    if mb.is_null() { return 0; }
    let count = if mb_len < 0 {
        let mut l = 0;
        while *mb.add(l) != 0 { l += 1; }
        l + 1
    } else {
        mb_len as usize
    };
    if wc.is_null() || wc_len == 0 { return count as i32; }
    let n = count.min(wc_len as usize);
    for i in 0..n {
        *wc.add(i) = *mb.add(i) as u16;
    }
    n as i32
}

#[no_mangle]
pub unsafe extern "win64" fn WideCharToMultiByte(
    _cp: u32, _flags: u32, wc: *const u16, wc_len: i32,
    mb: *mut u8, mb_len: i32, _def_char: *const u8, _used_def: *mut i32,
) -> i32 {
    if wc.is_null() { return 0; }
    let count = if wc_len < 0 {
        let mut l = 0;
        while *wc.add(l) != 0 { l += 1; }
        l + 1
    } else {
        wc_len as usize
    };
    if mb.is_null() || mb_len == 0 { return count as i32; }
    let n = count.min(mb_len as usize);
    for i in 0..n {
        let c = *wc.add(i);
        *mb.add(i) = if c < 128 { c as u8 } else { b'?' };
    }
    n as i32
}

#[no_mangle]
pub unsafe extern "win64" fn lstrcmpW(s1: *const u16, s2: *const u16) -> i32 {
    let mut i = 0;
    loop {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);
        if c1 != c2 || c1 == 0 { return (c1 as i32) - (c2 as i32); }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "win64" fn lstrcmpiW(s1: *const u16, s2: *const u16) -> i32 {
    crate::crt::_wcsicmp(s1, s2)
}

#[no_mangle]
pub unsafe extern "win64" fn CmdBatNotification(_flag: u32) {}

#[no_mangle]
pub unsafe extern "win64" fn SetErrorMode(_mode: u32) -> u32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn GetConsoleTitleW(title: *mut u16, size: u32) -> u32 {
    static TITLE: [u16; 17] = [
        'C' as u16, 'o' as u16, 'm' as u16, 'm' as u16, 'a' as u16, 'n' as u16, 'd' as u16,
        ' ' as u16, 'P' as u16, 'r' as u16, 'o' as u16, 'm' as u16, 'p' as u16, 't' as u16,
        0, 0, 0,
    ];
    if title.is_null() || size < 15 { return 0; }
    for i in 0..15 { *title.add(i) = TITLE[i]; }
    14
}

#[no_mangle]
pub unsafe extern "win64" fn SetConsoleTitleW(_title: *const u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetConsoleWindow() -> usize { 0 }

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct FileTime {
    pub low_date_time: u32,
    pub high_date_time: u32,
}

#[repr(C)]
pub struct Win32FindDataW {
    pub file_attributes: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub file_size_high: u32,
    pub file_size_low: u32,
    pub reserved0: u32,
    pub reserved1: u32,
    pub file_name: [u16; 260],
    pub alternate_file_name: [u16; 14],
}

#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub reserved: *mut u16,
    pub desktop: *mut u16,
    pub title: *mut u16,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: u32,
    pub show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub std_input: usize,
    pub std_output: usize,
    pub std_error: usize,
}

#[repr(C)]
pub struct Win32FileAttributeData {
    pub file_attributes: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub file_size_high: u32,
    pub file_size_low: u32,
}

#[repr(C)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

#[no_mangle]
pub unsafe extern "win64" fn CreateHardLinkW(_to: *const u16, _from: *const u16, _sec: *mut core::ffi::c_void) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn CreateSymbolicLinkW(_sym: *const u16, _target: *const u16, _flags: u32) -> u8 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn ResumeThread(_thread: usize) -> u32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn SetProcessAffinityMask(_process: usize, _mask: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetNumaNodeProcessorMaskEx(_node: u16, group_affinity: *mut GroupAffinity) -> i32 {
    if !group_affinity.is_null() {
        (*group_affinity).mask = 1;
        (*group_affinity).group = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetThreadGroupAffinity(_thread: usize, group_affinity: *mut GroupAffinity) -> i32 {
    if !group_affinity.is_null() {
        (*group_affinity).mask = 1;
        (*group_affinity).group = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn FindFirstFileExW(_name: *const u16, _lvl: i32, _data: *mut Win32FindDataW, _search_op: i32, _filter: *mut core::ffi::c_void, _flags: u32) -> usize {
    LAST_ERROR = 2; // ERROR_FILE_NOT_FOUND
    !0usize
}

#[no_mangle]
pub unsafe extern "win64" fn FindFirstStreamW(_name: *const u16, _info_lvl: i32, _find_stream_data: *mut core::ffi::c_void, _flags: u32) -> usize {
    LAST_ERROR = 2; // ERROR_FILE_NOT_FOUND
    !0usize
}

#[no_mangle]
pub unsafe extern "win64" fn FindNextStreamW(_handle: usize, _find_stream_data: *mut core::ffi::c_void) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn DeviceIoControl(_handle: usize, _code: u32, _in_buf: *const core::ffi::c_void, _in_len: u32, _out_buf: *mut core::ffi::c_void, _out_len: u32, bytes_ret: *mut u32, _ov: *mut core::ffi::c_void) -> i32 {
    if !bytes_ret.is_null() { *bytes_ret = 0; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn CompareFileTime(ft1: *const FileTime, ft2: *const FileTime) -> i32 {
    if ft1.is_null() || ft2.is_null() { return 0; }
    let t1 = ((*ft1).high_date_time as u64) << 32 | (*ft1).low_date_time as u64;
    let t2 = ((*ft2).high_date_time as u64) << 32 | (*ft2).low_date_time as u64;
    if t1 < t2 { -1 } else if t1 > t2 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "win64" fn RemoveDirectoryW(_path: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn GetExitCodeProcess(_handle: usize, exit_code: *mut u32) -> i32 {
    if !exit_code.is_null() { *exit_code = 0; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn SetFileTime(_handle: usize, _c: *const FileTime, _a: *const FileTime, _w: *const FileTime) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn DeleteFileW(_path: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn SetEndOfFile(_handle: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn SetFileAttributesW(_path: *const u16, _attrs: u32) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn CopyFileW(_existing: *const u16, _new: *const u16, _fail_if_exists: i32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn CreateDirectoryW(_path: *const u16, _sec: *mut core::ffi::c_void) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn DuplicateHandle(_src_proc: usize, src_h: usize, _tgt_proc: usize, tgt_h: *mut usize, _access: u32, _inherit: i32, _options: u32) -> i32 {
    if !tgt_h.is_null() { *tgt_h = src_h; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetFileAttributesExW(_path: *const u16, _level: i32, data: *mut Win32FileAttributeData) -> i32 {
    if !data.is_null() {
        (*data).file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        (*data).file_size_high = 0;
        (*data).file_size_low = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn ExpandEnvironmentStringsW(src: *const u16, dst: *mut u16, dst_size: u32) -> u32 {
    if src.is_null() { return 0; }
    let mut len = 0;
    while *src.add(len) != 0 { len += 1; }
    if dst.is_null() || dst_size <= len as u32 {
        return (len + 1) as u32;
    }
    for i in 0..len { *dst.add(i) = *src.add(i); }
    *dst.add(len) = 0;
    (len + 1) as u32
}

#[no_mangle]
pub unsafe extern "win64" fn CancelSynchronousIo(_thread: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn SetFilePointerEx(_handle: usize, distance: i64, new_pos: *mut i64, _method: u32) -> i32 {
    if !new_pos.is_null() { *new_pos = distance; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn SearchPathW(_path: *const u16, _file: *const u16, _ext: *const u16, _buf_len: u32, _buf: *mut u16, _file_part: *mut *mut u16) -> u32 {
    LAST_ERROR = 2; // ERROR_FILE_NOT_FOUND
    0
}

#[no_mangle]
pub unsafe extern "win64" fn MoveFileExW(_existing: *const u16, _new: *const u16, _flags: u32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn MoveFileW(_existing: *const u16, _new: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn QueryFullProcessImageNameW(_process: usize, _flags: u32, name: *mut u16, size: *mut u32) -> i32 {
    static CMD_PATH: [u16; 30] = [
        b"C"[0] as u16, b":"[0] as u16, b"\\"[0] as u16, b"W"[0] as u16, b"i"[0] as u16, b"n"[0] as u16, b"d"[0] as u16, b"o"[0] as u16, b"w"[0] as u16, b"s"[0] as u16,
        b"\\"[0] as u16, b"S"[0] as u16, b"y"[0] as u16, b"s"[0] as u16, b"t"[0] as u16, b"e"[0] as u16, b"m"[0] as u16, b"3"[0] as u16, b"2"[0] as u16,
        b"\\"[0] as u16, b"c"[0] as u16, b"m"[0] as u16, b"d"[0] as u16, b"."[0] as u16, b"e"[0] as u16, b"x"[0] as u16, b"e"[0] as u16, 0, 0, 0
    ];
    if name.is_null() || size.is_null() || *size < 28 { return 0; }
    for i in 0..27 { *name.add(i) = CMD_PATH[i]; }
    *name.add(27) = 0;
    *size = 27;
    1
}

#[no_mangle]
pub unsafe extern "win64" fn ReadProcessMemory(_proc: usize, _base: *const core::ffi::c_void, _buf: *mut core::ffi::c_void, _size: usize, read: *mut usize) -> i32 {
    if !read.is_null() { *read = 0; }
    0
}

#[no_mangle]
pub unsafe extern "win64" fn SetFilePointer(_handle: usize, distance: i32, high_distance: *mut i32, _method: u32) -> u32 {
    if !high_distance.is_null() { *high_distance = 0; }
    distance as u32
}

#[no_mangle]
pub unsafe extern "win64" fn FindFirstFileW(_path: *const u16, _data: *mut Win32FindDataW) -> usize {
    LAST_ERROR = 2; // ERROR_FILE_NOT_FOUND
    !0usize
}

#[no_mangle]
pub unsafe extern "win64" fn FindNextFileW(_handle: usize, _data: *mut Win32FindDataW) -> i32 {
    LAST_ERROR = 18; // ERROR_NO_MORE_FILES
    0
}

#[no_mangle]
pub unsafe extern "win64" fn FindClose(_handle: usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn CreateFileW(
    _filename: *const u16,
    _desired_access: u32,
    _share_mode: u32,
    _security_attributes: *mut core::ffi::c_void,
    _creation_disposition: u32,
    _flags_and_attributes: u32,
    _template_file: usize,
) -> usize {
    4usize
}

#[no_mangle]
pub unsafe extern "win64" fn GetFileSize(_handle: usize, high_size: *mut u32) -> u32 {
    if !high_size.is_null() { *high_size = 0; }
    0
}

#[no_mangle]
pub unsafe extern "win64" fn SetLocalTime(_st: *const SystemTime) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetSystemTime(st: *mut SystemTime) {
    if !st.is_null() {
        (*st).year = 2026;
        (*st).month = 11;
        (*st).day_of_week = 0;
        (*st).day = 22;
        (*st).hour = 21;
        (*st).minute = 30;
        (*st).second = 0;
        (*st).milliseconds = 0;
    }
}

#[no_mangle]
pub unsafe extern "win64" fn GetLocalTime(st: *mut SystemTime) {
    GetSystemTime(st);
}

#[no_mangle]
pub unsafe extern "win64" fn SystemTimeToFileTime(_st: *const SystemTime, ft: *mut FileTime) -> i32 {
    if !ft.is_null() {
        (*ft).low_date_time = 0x80000000;
        (*ft).high_date_time = 0x01DA0000;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn FileTimeToLocalFileTime(ft_in: *const FileTime, ft_out: *mut FileTime) -> i32 {
    if !ft_in.is_null() && !ft_out.is_null() {
        *ft_out = *ft_in;
    }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn FileTimeToSystemTime(_ft: *const FileTime, st: *mut SystemTime) -> i32 {
    GetSystemTime(st);
    1
}

#[no_mangle]
pub unsafe extern "win64" fn GetNumaHighestNodeNumber(highest_node: *mut u32) -> i32 {
    if !highest_node.is_null() { *highest_node = 0; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn SetEnvironmentStringsW(_env: *mut u16) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn GetVDMCurrentDirectories(_size: u32, _buf: *mut u16) -> u32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn InitializeProcThreadAttributeList(_list: *mut core::ffi::c_void, _count: u32, _flags: u32, size: *mut usize) -> i32 {
    if !size.is_null() { *size = 64; }
    1
}

#[no_mangle]
pub unsafe extern "win64" fn UpdateProcThreadAttribute(_list: *mut core::ffi::c_void, _flags: u32, _attr: usize, _val: *const core::ffi::c_void, _size: usize, _prev: *mut core::ffi::c_void, _ret_size: *mut usize) -> i32 { 1 }

#[no_mangle]
pub unsafe extern "win64" fn DeleteProcThreadAttributeList(_list: *mut core::ffi::c_void) {}

#[no_mangle]
pub unsafe extern "win64" fn GetStartupInfoW(si: *mut StartupInfoW) {
    if !si.is_null() {
        core::ptr::write_bytes(si as *mut u8, 0, core::mem::size_of::<StartupInfoW>());
        (*si).cb = core::mem::size_of::<StartupInfoW>() as u32;
        (*si).std_input = 3;
        (*si).std_output = 4;
        (*si).std_error = 4;
    }
}

#[no_mangle]
pub unsafe extern "win64" fn CreateProcessW(
    _app_name: *const u16,
    _cmd_line: *mut u16,
    _proc_sec: *mut core::ffi::c_void,
    _thread_sec: *mut core::ffi::c_void,
    _inherit_handles: i32,
    _flags: u32,
    _env: *mut core::ffi::c_void,
    _current_dir: *const u16,
    _startup_info: *const StartupInfoW,
    _proc_info: *mut core::ffi::c_void,
) -> i32 {
    LAST_ERROR = 120; // ERROR_CALL_NOT_IMPLEMENTED
    0
}

#[no_mangle]
pub unsafe extern "win64" fn GetFileAttributesW(_path: *const u16) -> u32 {
    0x80 // FILE_ATTRIBUTE_NORMAL
}

#[no_mangle]
pub unsafe extern "win64" fn NeedCurrentDirectoryForExePathW(_name: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "win64" fn GetBinaryTypeW(_path: *const u16, bin_type: *mut u32) -> i32 {
    if !bin_type.is_null() { *bin_type = 0; }
    0
}
