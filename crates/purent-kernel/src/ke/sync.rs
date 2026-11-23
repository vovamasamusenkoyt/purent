//! NT Kernel Synchronization Primitives and Bug Check

use core::sync::atomic::{AtomicI32, Ordering};

use purent_hal::kprintln;
use purent_ntdef::status::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS, STATUS_TIMEOUT};

/// NT x64 DISPATCHER_HEADER for notification and synchronization events.
#[repr(C)]
pub struct KernelEvent {
    kind: u8,
    control: u8,
    size: u8,
    reserved: u8,
    pub(crate) signal: AtomicI32,
    wait_list: purent_ntdef::list::ListEntry,
}

impl KernelEvent {
    pub(crate) fn ticks() -> u64 {
        unsafe { core::ptr::read_volatile(&raw const purent_hal::idt::TIMER_TICKS) }
    }

    pub fn is_signaled(&self) -> bool {
        self.signal.load(Ordering::Acquire) > 0
    }

    fn acquire(&self) -> bool {
        if self.kind == 0 {
            self.is_signaled()
        } else {
            self.signal.compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire).is_ok()
        }
    }
}

const _: () = assert!(core::mem::size_of::<KernelEvent>() == 24);

#[no_mangle]
pub unsafe extern "win64" fn KeInitializeEvent(
    event: *mut core::ffi::c_void,
    event_type: u32,
    initial_state: u8,
) {
    let event = event.cast::<KernelEvent>();
    if !event.is_null() {
        let wait_list = &raw mut (*event).wait_list;
        event.write(KernelEvent {
            kind: event_type as u8,
            control: 0,
            size: 6,
            reserved: 0,
            signal: AtomicI32::new(i32::from(initial_state != 0)),
            wait_list: purent_ntdef::list::ListEntry { flink: wait_list, blink: wait_list },
        });
    }
}

#[no_mangle]
pub unsafe extern "win64" fn KeSetEvent(
    event: *mut core::ffi::c_void,
    _increment: i32,
    _wait: u8,
) -> i32 {
    event.cast::<KernelEvent>().as_ref().map_or(0, |event| {
        event.signal.swap(1, Ordering::Release)
    })
}

#[no_mangle]
pub unsafe extern "win64" fn KeWaitForSingleObject(
    object: *mut core::ffi::c_void,
    _wait_reason: u32,
    _wait_mode: i8,
    _alertable: u8,
    timeout: *mut i64,
) -> NtStatus {
    let Some(event) = object.cast::<KernelEvent>().as_ref() else {
        return STATUS_INVALID_PARAMETER;
    };
    if event.kind > 1 || event.size != 6 {
        return STATUS_NOT_SUPPORTED;
    }

    let duration = match timeout.as_ref().copied() {
        None => None,
        Some(value) if value <= 0 => Some(value.unsigned_abs().div_ceil(100_000)),
        Some(_) => return STATUS_NOT_SUPPORTED,
    };
    let start = KernelEvent::ticks();
    loop {
        if event.acquire() {
            return STATUS_SUCCESS;
        }
        if duration.is_some_and(|ticks| KernelEvent::ticks().wrapping_sub(start) >= ticks) {
            return STATUS_TIMEOUT;
        }
        super::sched::wait_for_event_tick(event, start, duration);
    }
}

#[no_mangle]
pub unsafe extern "win64" fn KeEnterCriticalRegion() {}

#[no_mangle]
pub unsafe extern "win64" fn KeLeaveCriticalRegion() {}

#[no_mangle]
pub unsafe extern "win64" fn KeBugCheckEx(
    bug_check_code: u32,
    p1: usize,
    p2: usize,
    p3: usize,
    p4: usize,
) -> ! {
    kprintln!("\n*** STOP: 0x{:08X} (0x{:X}, 0x{:X}, 0x{:X}, 0x{:X})", bug_check_code, p1, p2, p3, p4);
    purent_hal::hlt_loop();
}
