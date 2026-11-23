//! PureNT Clean-Room WINBRAND Subsystem (WINBRAND.dll)

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetProcessHeap() -> usize;
    fn HeapAlloc(heap: usize, flags: u32, bytes: usize) -> *mut core::ffi::c_void;
}

#[no_mangle]
pub unsafe extern "win64" fn BrandingFormatString(_format: *const u16) -> *mut u16 {
    static BRANDING: [u16; 45] = [
        'M' as u16, 'i' as u16, 'c' as u16, 'r' as u16, 'o' as u16, 's' as u16, 'o' as u16, 'f' as u16, 't' as u16, ' ' as u16,
        'C' as u16, 'o' as u16, 'r' as u16, 'p' as u16, 'o' as u16, 'r' as u16, 'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, '.' as u16, ' ' as u16,
        'A' as u16, 'l' as u16, 'l' as u16, ' ' as u16, 'r' as u16, 'i' as u16, 'g' as u16, 'h' as u16, 't' as u16, 's' as u16, ' ' as u16,
        'r' as u16, 'e' as u16, 's' as u16, 'e' as u16, 'r' as u16, 'v' as u16, 'e' as u16, 'd' as u16, '.' as u16, 0, 0,
    ];
    let heap = GetProcessHeap();
    let ptr = HeapAlloc(heap, 0, core::mem::size_of_val(&BRANDING)) as *mut u16;
    if !ptr.is_null() {
        core::ptr::copy_nonoverlapping(BRANDING.as_ptr(), ptr, BRANDING.len());
    }
    ptr
}
