//! PureNT Clean-Room C Run-Time (CRT) Emulation Subsystem (msvcrt.dll)
//! Reverse-engineered specifications for Windows 7 SP1 x64 cmd.exe execution

use purent_ntdef::syscall::nt_syscall2;

#[no_mangle]
#[allow(suspicious_runtime_symbol_definitions)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

#[path = "../../purent-ntdef/src/freestanding.rs"]
mod freestanding;
pub use freestanding::*;

#[no_mangle]
pub static mut _fmode: i32 = 0;
#[no_mangle]
pub static mut _commode: i32 = 0;
#[no_mangle]
pub static mut _errno: i32 = 0;
// Fake CRT _iob array for stdin (0), stdout (1), stderr (2)
#[repr(C)]
pub struct FILE {
    pub ptr: *mut u8,
    pub cnt: i32,
    pub base: *mut u8,
    pub flag: i32,
    pub file: i32,
    pub charbuf: i32,
    pub bufsiz: i32,
    pub tmpfname: *mut u8,
}

#[no_mangle]
pub static mut _iob: [FILE; 3] = [
    FILE { ptr: core::ptr::null_mut(), cnt: 0, base: core::ptr::null_mut(), flag: 1, file: 0, charbuf: 0, bufsiz: 0, tmpfname: core::ptr::null_mut() },
    FILE { ptr: core::ptr::null_mut(), cnt: 0, base: core::ptr::null_mut(), flag: 2, file: 1, charbuf: 0, bufsiz: 0, tmpfname: core::ptr::null_mut() },
    FILE { ptr: core::ptr::null_mut(), cnt: 0, base: core::ptr::null_mut(), flag: 2, file: 2, charbuf: 0, bufsiz: 0, tmpfname: core::ptr::null_mut() },
];

#[no_mangle]
pub unsafe extern "C" fn __set_app_type(_app_type: u32) {}

#[no_mangle]
pub unsafe extern "C" fn __setusermatherr(_handler: usize) {}

#[no_mangle]
pub unsafe extern "C" fn _amsg_exit(_code: i32) {}

#[no_mangle]
pub unsafe extern "C" fn _initterm(start: *const extern "C" fn(), end: *const extern "C" fn()) {
    if start.is_null() || end.is_null() {
        return;
    }
    let mut cur = start;
    while cur < end {
        let func = *cur;
        if func as usize != 0 {
            func();
        }
        cur = cur.add(1);
    }
}

#[no_mangle]
pub unsafe extern "C" fn _cexit() {}

#[no_mangle]
pub unsafe extern "C" fn _exit(code: i32) -> ! {
    exit(code)
}

#[no_mangle]
pub unsafe extern "C" fn exit(code: i32) -> ! {
    nt_syscall2(0x29, !0u64, code as u64); // NtTerminateProcess(NtCurrentProcess, code)
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn _XcptFilter(_exc: u32, _info: usize) -> i32 {
    1 // EXCEPTION_EXECUTE_HANDLER
}

#[no_mangle]
pub unsafe extern "C" fn __C_specific_handler() -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn __getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut u8,
    envp: *mut *mut *mut u8,
    _dowildcard: i32,
    _startupinfo: *mut core::ffi::c_void,
) -> i32 {
    static mut EMPTY_ARGV: [*mut u8; 2] = [core::ptr::null_mut(), core::ptr::null_mut()];
    static mut EMPTY_ENVP: [*mut u8; 1] = [core::ptr::null_mut()];
    if !argc.is_null() { *argc = 1; }
    if !argv.is_null() { *argv = &raw mut EMPTY_ARGV as *mut *mut u8; }
    if !envp.is_null() { *envp = &raw mut EMPTY_ENVP as *mut *mut u8; }
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn _setjmp() -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn longjmp() -> ! {
    exit(1)
}

#[no_mangle]
pub unsafe extern "C" fn _local_unwind() {}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn _ZNSt9terminateEv() {}

#[no_mangle]
pub unsafe extern "C" fn qsort(
    _base: *mut core::ffi::c_void,
    _num: usize,
    _size: usize,
    _compar: usize,
) {}

#[no_mangle]
pub unsafe extern "C" fn _dup(fd: i32) -> i32 { fd }

#[no_mangle]
pub unsafe extern "C" fn _dup2(fd1: i32, _fd2: i32) -> i32 { fd1 }

#[no_mangle]
pub unsafe extern "C" fn _close(_fd: i32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn _open_osfhandle(osfhandle: usize, _flags: i32) -> i32 {
    osfhandle as i32
}

#[no_mangle]
pub unsafe extern "C" fn _get_osfhandle(fd: i32) -> usize {
    match fd {
        0 => 0x03, // STD_INPUT_HANDLE
        1 => 0x04, // STD_OUTPUT_HANDLE
        2 => 0x04, // STD_ERROR_HANDLE
        _ => fd as usize,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _pipe(_ptflags: *mut i32, _psize: u32, _textmode: i32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn _setmode(_fd: i32, _mode: i32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn _tell(_fd: i32) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn _getch() -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn time(_t: *mut i64) -> i64 { 0 }

#[no_mangle]
pub unsafe extern "C" fn srand(_seed: u32) {}

#[no_mangle]
pub unsafe extern "C" fn rand() -> i32 { 42 }

#[no_mangle]
pub unsafe extern "C" fn setlocale(_category: i32, _locale: *const u8) -> *const u8 {
    b"C\0".as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn fflush(_stream: *mut FILE) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn ferror(_stream: *mut FILE) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn feof(_stream: *mut FILE) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn fgets(str: *mut u8, num: i32, _stream: *mut FILE) -> *mut u8 {
    if !str.is_null() && num > 0 {
        *str = 0;
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn printf(_format: *const u8) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn fprintf(_stream: *mut FILE, _format: *const u8) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn swscanf(_ws: *const u16, _format: *const u16) -> i32 { 0 }

#[no_mangle]
pub unsafe extern "C" fn _wpopen(_cmd: *const u16, _mode: *const u16) -> *mut FILE {
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn _pclose(_stream: *mut FILE) -> i32 { 0 }

// Memory management from simple bump allocator (backed by NtAllocateVirtualMemory)
#[no_mangle]
pub unsafe extern "C" fn calloc(num: usize, size: usize) -> *mut core::ffi::c_void {
    let total = num * size;
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size = (total + 4095) & !4095;
    let st = purent_ntdef::syscall::nt_syscall6(
        0x15, // NtAllocateVirtualMemory
        0,    // NtCurrentProcess
        &mut base as *mut _ as u64,
        0,
        &mut region_size as *mut _ as u64,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04,   // PAGE_READWRITE
    );
    if st == 0 {
        base
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn free(_ptr: *mut core::ffi::c_void) {}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut core::ffi::c_void, size: usize) -> *mut core::ffi::c_void {
    if ptr.is_null() {
        return calloc(1, size);
    }
    ptr
}

// Wide string functions
#[no_mangle]
pub unsafe extern "C" fn _wcslwr(s: *mut u16) -> *mut u16 {
    if s.is_null() { return s; }
    let mut p = s;
    while *p != 0 {
        if *p >= 'A' as u16 && *p <= 'Z' as u16 {
            *p += ('a' as u16) - ('A' as u16);
        }
        p = p.add(1);
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn _wcsupr(s: *mut u16) -> *mut u16 {
    if s.is_null() { return s; }
    let mut p = s;
    while *p != 0 {
        if *p >= 'a' as u16 && *p <= 'z' as u16 {
            *p -= ('a' as u16) - ('A' as u16);
        }
        p = p.add(1);
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    for i in 0..n {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);
        if c1 != c2 || c1 == 0 {
            return (c1 as i32) - (c2 as i32);
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
    let mut i = 0;
    loop {
        let mut c1 = *s1.add(i);
        let mut c2 = *s2.add(i);
        if c1 >= 'A' as u16 && c1 <= 'Z' as u16 { c1 += 32; }
        if c2 >= 'A' as u16 && c2 <= 'Z' as u16 { c2 += 32; }
        if c1 != c2 || c1 == 0 {
            return (c1 as i32) - (c2 as i32);
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn _wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    for i in 0..n {
        let mut c1 = *s1.add(i);
        let mut c2 = *s2.add(i);
        if c1 >= 'A' as u16 && c1 <= 'Z' as u16 { c1 += 32; }
        if c2 >= 'A' as u16 && c2 <= 'Z' as u16 { c2 += 32; }
        if c1 != c2 || c1 == 0 {
            return (c1 as i32) - (c2 as i32);
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn wcschr(s: *const u16, c: u16) -> *const u16 {
    let mut p = s;
    while *p != 0 {
        if *p == c { return p; }
        p = p.add(1);
    }
    if c == 0 { p } else { core::ptr::null() }
}

#[no_mangle]
pub unsafe extern "C" fn wcsrchr(s: *const u16, c: u16) -> *const u16 {
    let mut last = core::ptr::null();
    let mut p = s;
    while *p != 0 {
        if *p == c { last = p; }
        p = p.add(1);
    }
    if c == 0 { p } else { last }
}

#[no_mangle]
pub unsafe extern "C" fn wcsstr(haystack: *const u16, needle: *const u16) -> *const u16 {
    if *needle == 0 { return haystack; }
    let mut h = haystack;
    while *h != 0 {
        let mut h_sub = h;
        let mut n = needle;
        while *n != 0 && *h_sub == *n {
            h_sub = h_sub.add(1);
            n = n.add(1);
        }
        if *n == 0 { return h; }
        h = h.add(1);
    }
    core::ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn wcsspn(s: *const u16, accept: *const u16) -> usize {
    let mut count = 0;
    let mut p = s;
    while *p != 0 {
        if wcschr(accept, *p).is_null() { break; }
        count += 1;
        p = p.add(1);
    }
    count
}

#[no_mangle]
pub unsafe extern "C" fn towlower(c: u16) -> u16 {
    if c >= 'A' as u16 && c <= 'Z' as u16 { c + 32 } else { c }
}

#[no_mangle]
pub unsafe extern "C" fn towupper(c: u16) -> u16 {
    if c >= 'a' as u16 && c <= 'z' as u16 { c - 32 } else { c }
}

#[no_mangle]
pub unsafe extern "C" fn iswdigit(c: u16) -> i32 {
    if c >= '0' as u16 && c <= '9' as u16 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn iswxdigit(c: u16) -> i32 {
    if (c >= '0' as u16 && c <= '9' as u16)
        || (c >= 'a' as u16 && c <= 'f' as u16)
        || (c >= 'A' as u16 && c <= 'F' as u16)
    {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn iswspace(c: u16) -> i32 {
    if c == ' ' as u16 || c == '\t' as u16 || c == '\n' as u16 || c == '\r' as u16 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn iswalpha(c: u16) -> i32 {
    if (c >= 'a' as u16 && c <= 'z' as u16) || (c >= 'A' as u16 && c <= 'Z' as u16) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcstol(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> i32 {
    let mut p = nptr;
    while iswspace(*p) != 0 { p = p.add(1); }
    let mut sign = 1;
    if *p == '-' as u16 { sign = -1; p = p.add(1); }
    else if *p == '+' as u16 { p = p.add(1); }
    let b = if base == 0 { 10 } else { base };
    let mut res: i32 = 0;
    while iswdigit(*p) != 0 {
        res = res * b + (*p - '0' as u16) as i32;
        p = p.add(1);
    }
    if !endptr.is_null() { *endptr = p as *mut u16; }
    res * sign
}

#[no_mangle]
pub unsafe extern "C" fn wcstoul(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> u32 {
    wcstol(nptr, endptr, base) as u32
}

#[no_mangle]
pub unsafe extern "C" fn _wtol(s: *const u16) -> i32 {
    wcstol(s, core::ptr::null_mut(), 10)
}

#[no_mangle]
pub unsafe extern "C" fn _ultoa(val: u32, str: *mut u8, radix: i32) -> *mut u8 {
    let r = if radix < 2 || radix > 36 { 10 } else { radix as u32 };
    let mut buf = [0u8; 33];
    let mut idx = 0;
    let mut v = val;
    if v == 0 {
        *str = b'0';
        *str.add(1) = 0;
        return str;
    }
    while v > 0 {
        let rem = v % r;
        buf[idx] = if rem < 10 { b'0' + rem as u8 } else { b'a' + (rem - 10) as u8 };
        idx += 1;
        v /= r;
    }
    for i in 0..idx {
        *str.add(i) = buf[idx - 1 - i];
    }
    *str.add(idx) = 0;
    str
}

#[no_mangle]
pub unsafe extern "C" fn _vsnwprintf(
    buffer: *mut u16,
    count: usize,
    format: *const u16,
    argptr: usize,
) -> i32 {
    if buffer.is_null() || count == 0 { return 0; }
    let args = argptr as *const usize;
    let mut in_idx = 0;
    let mut out_idx = 0;
    let mut arg_idx = 0;

    while out_idx + 1 < count && *format.add(in_idx) != 0 {
        let ch = *format.add(in_idx);
        if ch == '%' as u16 {
            in_idx += 1;
            let mut min_digits = 0;
            if *format.add(in_idx) == '0' as u16 {
                in_idx += 1;
                while *format.add(in_idx) >= '0' as u16 && *format.add(in_idx) <= '9' as u16 {
                    min_digits = min_digits * 10 + (*format.add(in_idx) - '0' as u16) as usize;
                    in_idx += 1;
                }
            }
            let spec = *format.add(in_idx);
            in_idx += 1;

            if spec == 's' as u16 || (spec == 'w' as u16 && *format.add(in_idx) == 's' as u16) {
                if spec == 'w' as u16 { in_idx += 1; }
                if !args.is_null() {
                    let insert_str = *args.add(arg_idx) as *const u16;
                    arg_idx += 1;
                    if !insert_str.is_null() {
                        let mut s = 0;
                        while out_idx + 1 < count && *insert_str.add(s) != 0 {
                            *buffer.add(out_idx) = *insert_str.add(s);
                            out_idx += 1;
                            s += 1;
                        }
                    }
                }
                continue;
            } else if spec == 'd' as u16 || spec == 'i' as u16 || spec == 'u' as u16 {
                if !args.is_null() {
                    let val = *args.add(arg_idx) as i64;
                    arg_idx += 1;
                    let mut temp = [0u16; 32];
                    let mut n = if val < 0 && spec != 'u' as u16 { (-val) as u64 } else { val as u64 };
                    let mut tlen = 0;
                    if n == 0 {
                        temp[tlen] = '0' as u16;
                        tlen += 1;
                    } else {
                        while n > 0 {
                            temp[tlen] = ('0' as u16) + (n % 10) as u16;
                            n /= 10;
                            tlen += 1;
                        }
                    }
                    while tlen < min_digits && tlen < 31 {
                        temp[tlen] = '0' as u16;
                        tlen += 1;
                    }
                    if val < 0 && spec != 'u' as u16 && out_idx + 1 < count {
                        *buffer.add(out_idx) = '-' as u16;
                        out_idx += 1;
                    }
                    let mut k = tlen;
                    while k > 0 && out_idx + 1 < count {
                        k -= 1;
                        *buffer.add(out_idx) = temp[k];
                        out_idx += 1;
                    }
                }
                continue;
            } else if spec == '%' as u16 {
                *buffer.add(out_idx) = '%' as u16;
                out_idx += 1;
                continue;
            }
        }
        *buffer.add(out_idx) = ch;
        out_idx += 1;
        in_idx += 1;
    }
    *buffer.add(out_idx) = 0;
    out_idx as i32
}

static WINVER_NAME: [u16; 11] = [119, 105, 110, 118, 101, 114, 46, 101, 120, 101, 0];

#[no_mangle]
pub static mut _wcmdln: *const u16 = WINVER_NAME.as_ptr();

#[no_mangle]
pub unsafe extern "C" fn __wgetmainargs(
    argc: *mut i32,
    argv: *mut *mut *const u16,
    envp: *mut *mut *const u16,
    _expand: i32,
    _startup: usize,
) -> i32 {
    static mut ARGV: [*const u16; 2] = [WINVER_NAME.as_ptr(), core::ptr::null()];
    static mut ENVP: [*const u16; 1] = [core::ptr::null()];
    *argc = 1;
    *argv = (&raw mut ARGV).cast();
    *envp = (&raw mut ENVP).cast();
    0
}
