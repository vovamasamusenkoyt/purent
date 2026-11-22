//! Doubly linked circular list (LIST_ENTRY) used throughout NT

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

unsafe impl Send for ListEntry {}
unsafe impl Sync for ListEntry {}

impl ListEntry {
    pub const fn empty() -> Self {
        Self {
            flink: core::ptr::null_mut(),
            blink: core::ptr::null_mut(),
        }
    }

    #[inline(always)]
    pub unsafe fn initialize(entry: *mut ListEntry) {
        (*entry).flink = entry;
        (*entry).blink = entry;
    }

    #[inline(always)]
    pub unsafe fn is_empty(entry: *const ListEntry) -> bool {
        (*entry).flink == entry as *mut ListEntry
    }

    #[inline(always)]
    pub unsafe fn insert_tail(head: *mut ListEntry, entry: *mut ListEntry) {
        let blink = (*head).blink;
        (*entry).flink = head;
        (*entry).blink = blink;
        (*blink).flink = entry;
        (*head).blink = entry;
    }

    #[inline(always)]
    pub unsafe fn remove_entry(entry: *mut ListEntry) -> bool {
        let flink = (*entry).flink;
        let blink = (*entry).blink;
        (*blink).flink = flink;
        (*flink).blink = blink;
        flink == blink
    }
}
