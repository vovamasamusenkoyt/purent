//! Image catalog and process handles for the built-in Win32 executable service.

pub const SYSTEM_DIRECTORY: &[u8] = b"C:\\Windows\\System32\\";
pub const EXECUTABLES: &[&str] = &["winver.exe", "windowdemo.exe"];

pub const PROCESS_HANDLE_TAG: usize = 0x6000_0000;
pub const PROCESS_HANDLE_LIMIT: usize = 0x7000_0000;
pub const MAX_CHILD_PID: usize = (PROCESS_HANDLE_LIMIT - PROCESS_HANDLE_TAG - 1) >> 1;

pub fn child_handle(pid: usize, thread: bool) -> usize {
    PROCESS_HANDLE_TAG | (pid << 1) | usize::from(thread)
}

pub fn decode_child_handle(handle: usize) -> Option<(usize, usize)> {
    if !(PROCESS_HANDLE_TAG..PROCESS_HANDLE_LIMIT).contains(&handle) {
        return None;
    }
    let offset = handle - PROCESS_HANDLE_TAG;
    Some((offset >> 1, 1 << (offset & 1)))
}
