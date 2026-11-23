//! Hosted executable launch requests and child process handles.

use purent_hal::{kprintln, SpinLock};
use purent_ntdef::builtin_exec::{decode_child_handle, EXECUTABLES, MAX_CHILD_PID};
use purent_ntdef::kpcr::KThread;
use purent_ntdef::status::*;

const ENVIRONMENT_BASE: usize = 0x1550000;
const SLOTS: usize = 4;
const BOTH_HANDLES: usize = 3;
const WAIT_TIMEOUT: u64 = 258;
const STILL_ACTIVE: u64 = 259;

struct BuiltinImage {
    bytes: &'static [u8],
    available: bool,
}

const IMAGES: &[BuiltinImage] = &[
    BuiltinImage {
        bytes: crate::WINVER_EXE_BYTES,
        available: !crate::WINVER_EXE_BYTES.is_empty() && !crate::WINVER_MUI_BYTES.is_empty(),
    },
    BuiltinImage {
        bytes: include_bytes!("../../../../target/esp/windowdemo.exe"),
        available: true,
    },
];

const _: () = assert!(IMAGES.len() == EXECUTABLES.len());

#[derive(Clone, Copy)]
enum State {
    Free,
    Queued,
    Starting,
    Running(usize),
    Exited(u32),
    Failed(NtStatus),
}

#[derive(Clone, Copy)]
struct Child {
    pid: usize,
    catalog: usize,
    handles: usize,
    state: State,
}

const EMPTY: Child = Child {
    pid: 0,
    catalog: 0,
    handles: 0,
    state: State::Free,
};

struct Children {
    next_pid: usize,
    slots: [Child; SLOTS],
}

static CHILDREN: SpinLock<Children> = SpinLock::new(Children {
    next_pid: 0x800,
    slots: [EMPTY; SLOTS],
});

fn missing() -> NtStatus {
    STATUS_OBJECT_NAME_NOT_FOUND
}

pub fn image_size(index: usize) -> NtStatus {
    IMAGES
        .get(index)
        .filter(|image| image.available)
        .map_or(STATUS_OBJECT_NAME_NOT_FOUND, |image| {
            image.bytes.len() as NtStatus
        })
}

pub fn image_for_pid(pid: usize) -> Option<&'static [u8]> {
    let children = CHILDREN.lock();
    children.slots.iter().find_map(|child| {
        (child.pid == pid && matches!(child.state, State::Starting | State::Running(_)))
            .then(|| IMAGES[child.catalog].bytes)
    })
}

pub fn request(index: usize) -> NtStatus {
    if image_size(index) <= 0 {
        return missing();
    }
    let (slot, pid) = {
        let mut children = CHILDREN.lock();
        let Some(slot) = children
            .slots
            .iter()
            .position(|child| matches!(child.state, State::Free))
        else {
            return STATUS_NO_MEMORY;
        };
        let pid = children.next_pid;
        if pid > MAX_CHILD_PID {
            return STATUS_NO_MEMORY;
        }
        children.next_pid += 8;
        children.slots[slot] = Child {
            pid,
            catalog: index,
            handles: BOTH_HANDLES,
            state: State::Queued,
        };
        (slot, pid)
    };

    loop {
        {
            let mut children = CHILDREN.lock();
            match children.slots[slot].state {
                State::Running(_) | State::Exited(_) => return pid as NtStatus,
                State::Failed(status) => {
                    children.slots[slot] = EMPTY;
                    return status;
                }
                _ => {}
            }
        }
        unsafe { purent_hal::cpu::halt() };
    }
}

pub fn wait(handle: usize, milliseconds: u32) -> u64 {
    let start = ticks();
    loop {
        match state_for_handle(handle) {
            None => return STATUS_INVALID_HANDLE as u64,
            Some(State::Exited(_)) => return 0,
            Some(_) => {}
        }
        if milliseconds != u32::MAX
            && ticks().wrapping_sub(start) >= u64::from(milliseconds.div_ceil(10))
        {
            return WAIT_TIMEOUT;
        }
        unsafe { purent_hal::cpu::halt() };
    }
}

fn ticks() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS) }
}

fn state_for_handle(handle: usize) -> Option<State> {
    let (pid, bit) = decode_child_handle(handle)?;
    CHILDREN
        .lock()
        .slots
        .iter()
        .find(|child| child.pid == pid && child.handles & bit != 0)
        .map(|child| child.state)
}

pub fn exit_code(handle: usize) -> u64 {
    if decode_child_handle(handle).is_none_or(|(_, bit)| bit != 1) {
        return STATUS_INVALID_HANDLE as u64;
    }
    match state_for_handle(handle) {
        Some(State::Exited(code)) => u64::from(code),
        Some(_) => STILL_ACTIVE,
        None => STATUS_INVALID_HANDLE as u64,
    }
}

pub fn close(handle: usize) -> NtStatus {
    let Some((pid, bit)) = decode_child_handle(handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let mut children = CHILDREN.lock();
    let Some(child) = children
        .slots
        .iter_mut()
        .find(|child| child.pid == pid && child.handles & bit != 0)
    else {
        return STATUS_INVALID_HANDLE;
    };
    child.handles &= !bit;
    if child.handles == 0 && matches!(child.state, State::Exited(_)) {
        *child = EMPTY;
    }
    STATUS_SUCCESS
}

/// Called by the system desktop thread, which is also responsible for reaping.
pub unsafe fn service() {
    let request = {
        let mut children = CHILDREN.lock();
        children
            .slots
            .iter_mut()
            .enumerate()
            .find_map(|(slot, child)| {
                matches!(child.state, State::Queued).then(|| {
                    child.state = State::Starting;
                    (slot, child.pid, child.catalog)
                })
            })
    };
    if let Some((slot, pid, catalog)) = request {
        let result = (|| {
            let cr3 = crate::mm::create_user_address_space()?;
            let result = (|| {
                super::ps_map_user_shared_data(cr3)?;
                let loader_entry = super::ps_load_ntdll(cr3)?;
                super::ps_create_win32_process(
                    IMAGES[catalog].bytes,
                    EXECUTABLES[catalog],
                    pid,
                    ENVIRONMENT_BASE,
                    loader_entry,
                    cr3,
                )
            })();
            if result.is_err() {
                crate::mm::destroy_user_address_space(cr3);
            }
            result
        })();
        kprintln!(
            "[BUILTIN] Launching {} (PID 0x{:X}): status 0x{:08X}",
            EXECUTABLES[catalog],
            pid,
            match &result { Ok(_) => 0, Err(e) => *e }
        );
        CHILDREN.lock().slots[slot].state = match result {
            Ok((_, thread)) => State::Running(thread as usize),
            Err(status) => State::Failed(status),
        };
    }

    for index in 0..SLOTS {
        let child = CHILDREN.lock().slots[index];
        let State::Running(thread) = child.state else {
            continue;
        };
        let thread = thread as *mut KThread;
        if core::ptr::read_volatile(&raw const (*thread).header[4]) == 0 {
            continue;
        }

        let process = (*thread).process.cast::<super::Process>();
        let code = (*process).exit_status;
        let cr3 = (*process).pcb.directory_table_base;
        crate::win32k::windows::remove_process(child.pid);
        crate::mm::destroy_user_address_space(cr3);
        super::ps_reap_thread(thread);
        let mut children = CHILDREN.lock();
        let child = &mut children.slots[index];
        kprintln!(
            "[PS] Child PID 0x{:X} exited with 0x{:08X}; released image and process pages",
            child.pid,
            code
        );
        if child.handles == 0 {
            *child = EMPTY;
        } else {
            child.state = State::Exited(code);
        }
    }
}
