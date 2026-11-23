//! Ring 3 loader for the built-in Win32 DLL catalog.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use purent_ntdef::list::ListEntry;
use purent_ntdef::ps::{LdrDataTableEntry, Peb, PebLdrData};
use purent_ntdef::status::{
    NtStatus, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use purent_ntdef::string::{AnsiString, UnicodeString};
use purent_ntdef::syscall::{
    nt_current_peb_address, nt_syscall1, nt_syscall2, CURRENT_EXECUTABLE_IMAGE,
    SYSCALL_PURENT_MAP_DLL, SYSCALL_PURENT_SEAL_IMAGE,
};
use purent_ntdef::win32_modules::{module_import_host, module_name_matches, BUILTIN_MODULES};
use purent_pe::{ImageImportDescriptor, NamedExport, PeView, IMAGE_DIRECTORY_ENTRY_IMPORT};

const MODULE_COUNT: usize = BUILTIN_MODULES.len();
const LOADER_DATA_OFFSET: usize = 0x800;
const ORDINAL_IMPORT: u64 = 1 << 63;

#[repr(C)]
struct ModuleRecord {
    entry: LdrDataTableEntry,
    name: [u16; 48],
}

#[repr(C)]
struct LoaderData {
    ldr: PebLdrData,
    executable: ModuleRecord,
    modules: [ModuleRecord; MODULE_COUNT],
}

const _: () = assert!(LOADER_DATA_OFFSET + size_of::<LoaderData>() <= 4096);

// Bind each DLL IAT once per address space. Loader lists belong to each PEB.
static LOCKED: AtomicBool = AtomicBool::new(false);
static mut READY: usize = 0;
static mut DEPENDENCIES: [usize; MODULE_COUNT] = [0; MODULE_COUNT];

struct LoaderLock;

impl LoaderLock {
    fn acquire() -> Self {
        while LOCKED.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for LoaderLock {
    fn drop(&mut self) {
        LOCKED.store(false, Ordering::Release);
    }
}

fn module_index(name: &str) -> Option<usize> {
    let name = module_import_host(name);
    BUILTIN_MODULES
        .iter()
        .position(|&(module, _)| module_name_matches(module, name))
}

fn status_result(status: NtStatus) -> Result<(), NtStatus> {
    if status < 0 {
        Err(status)
    } else {
        Ok(())
    }
}

struct Image {
    base: usize,
    size: usize,
    entry: usize,
}

impl Image {
    unsafe fn open(base: usize) -> Result<Self, NtStatus> {
        let headers = PeView::parse(core::slice::from_raw_parts(base as *const u8, 4096))
            .map_err(|_| STATUS_UNSUCCESSFUL)?;
        let size = headers.size_of_image() as usize;
        let rva = headers.entry_point_rva() as usize;
        if rva >= size {
            return Err(STATUS_UNSUCCESSFUL);
        }
        Ok(Self {
            base,
            size,
            entry: base + rva,
        })
    }

    fn address(&self, rva: usize, size: usize) -> Result<usize, NtStatus> {
        if rva.checked_add(size).is_none_or(|end| end > self.size) {
            Err(STATUS_UNSUCCESSFUL)
        } else {
            Ok(self.base + rva)
        }
    }

    unsafe fn read<T: Copy>(&self, rva: usize) -> Result<T, NtStatus> {
        let address = self.address(rva, size_of::<T>())?;
        Ok(ptr::read_unaligned(address as *const T))
    }

    unsafe fn string(&self, rva: usize) -> Result<&[u8], NtStatus> {
        self.address(rva, 1)?;
        let ptr = (self.base + rva) as *const u8;
        for len in 0..self.size.saturating_sub(rva).min(256) {
            if *ptr.add(len) == 0 {
                return Ok(core::slice::from_raw_parts(ptr, len));
            }
        }
        Err(STATUS_UNSUCCESSFUL)
    }

    unsafe fn export(&self, name: &[u8]) -> Result<NamedExport<'_>, NtStatus> {
        let data = core::slice::from_raw_parts(self.base as *const u8, self.size);
        PeView::parse(data)
            .map_err(|_| STATUS_UNSUCCESSFUL)?
            .named_export(name, true)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }
}

unsafe fn ensure_module(index: usize, loading: usize) -> Result<usize, NtStatus> {
    let (name, base) = BUILTIN_MODULES[index];
    let bit = 1usize << index;
    if READY & bit != 0 {
        return Ok(DEPENDENCIES[index] | bit);
    }
    if loading & bit != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    // The kernel has already mapped and protected the bootstrap image.
    if name == "ntdll.dll" {
        READY |= bit;
        return Ok(bit);
    }
    status_result(nt_syscall1(SYSCALL_PURENT_MAP_DLL, index as u64))?;
    let image = Image::open(base)?;
    let deps = bind_imports(&image, loading | bit, true)?;
    status_result(nt_syscall1(SYSCALL_PURENT_SEAL_IMAGE, index as u64))?;
    DEPENDENCIES[index] = deps;
    READY |= bit;
    Ok(deps | bit)
}

unsafe fn resolve(
    image: &Image,
    name: &[u8],
    loading: usize,
    forwards: usize,
    loaded: &mut usize,
) -> Result<usize, NtStatus> {
    if forwards >= MODULE_COUNT {
        return Err(STATUS_NOT_SUPPORTED);
    }
    match image.export(name)? {
        NamedExport::Address(rva) => image.address(rva as usize, 1),
        NamedExport::Forwarder(target) => {
            let (dll, symbol) = target.rsplit_once('.').ok_or(STATUS_UNSUCCESSFUL)?;
            let index = module_index(dll).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            *loaded |= ensure_module(index, loading)?;
            resolve(
                &Image::open(BUILTIN_MODULES[index].1)?,
                symbol.as_bytes(),
                loading,
                forwards + 1,
                loaded,
            )
        }
    }
}

unsafe fn bind_imports(image: &Image, loading: usize, is_dll: bool) -> Result<usize, NtStatus> {
    let headers = PeView::parse(core::slice::from_raw_parts(image.base as *const u8, 4096))
        .map_err(|_| STATUS_UNSUCCESSFUL)?;
    let Some(directory) = headers
        .data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .copied()
    else {
        return Ok(0);
    };
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(0);
    }
    let mut loaded = 0;
    let descriptor_size = size_of::<ImageImportDescriptor>();
    for offset in (0..directory.size as usize).step_by(descriptor_size) {
        if offset + descriptor_size > directory.size as usize {
            break;
        }
        let desc =
            image.read::<ImageImportDescriptor>(directory.virtual_address as usize + offset)?;
        if desc.name == 0 && desc.first_thunk == 0 {
            return Ok(loaded);
        }
        if desc.name == 0 || desc.first_thunk == 0 || (is_dll && desc.original_first_thunk == 0) {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let dll_name = core::str::from_utf8(image.string(desc.name as usize)?)
            .map_err(|_| STATUS_UNSUCCESSFUL)?;
        let index = module_index(dll_name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        loaded |= ensure_module(index, loading)?;
        let provider = Image::open(BUILTIN_MODULES[index].1)?;
        let lookup = if desc.original_first_thunk == 0 {
            desc.first_thunk
        } else {
            desc.original_first_thunk
        } as usize;
        let mut slot = 0;
        loop {
            let thunk = image.read::<u64>(lookup + slot)?;
            if thunk == 0 {
                break;
            }
            if thunk & ORDINAL_IMPORT != 0 || thunk > u32::MAX as u64 {
                return Err(STATUS_NOT_SUPPORTED);
            }
            let function = image.string(thunk as usize + 2)?;
            let address = resolve(&provider, function, loading, 0, &mut loaded)?;
            let iat = image.address(desc.first_thunk as usize + slot, size_of::<u64>())?;
            ptr::write_unaligned(iat as *mut u64, address as u64);
            slot += size_of::<u64>();
        }
    }
    Err(STATUS_UNSUCCESSFUL)
}

unsafe fn append_module(
    data: *mut LoaderData,
    record: *mut ModuleRecord,
    image: &Image,
    full_name: UnicodeString,
    dll: bool,
) {
    let entry = &raw mut (*record).entry;
    (*entry).dll_base = image.base as *mut c_void;
    (*entry).entry_point = image.entry as *mut c_void;
    (*entry).size_of_image = image.size as u32;
    (*entry).full_dll_name = full_name;
    let name = core::slice::from_raw_parts(full_name.buffer, full_name.length as usize / 2);
    let start = name
        .iter()
        .rposition(|&unit| unit == b'\\' as u16)
        .map_or(0, |slash| slash + 1);
    (*entry).base_dll_name = UnicodeString::from_raw_parts(
        full_name.buffer.add(start),
        full_name.length - (start * 2) as u16,
        full_name.maximum_length - (start * 2) as u16,
    );

    ListEntry::insert_tail(
        &raw mut (*data).ldr.in_load_order_module_list,
        &raw mut (*entry).in_load_order_links,
    );
    ListEntry::insert_tail(
        &raw mut (*data).ldr.in_memory_order_module_list,
        &raw mut (*entry).in_memory_order_links,
    );
    if dll {
        ListEntry::insert_tail(
            &raw mut (*data).ldr.in_initialization_order_module_list,
            &raw mut (*entry).in_initialization_order_links,
        );
    }
}

unsafe fn publish_modules(data: *mut LoaderData, loaded: usize) -> Result<(), NtStatus> {
    let ntdll = module_index("ntdll.dll").ok_or(STATUS_UNSUCCESSFUL)?;
    let order = core::iter::once(ntdll).chain((0..MODULE_COUNT).filter(|&index| index != ntdll));
    for index in order {
        let (name, base) = BUILTIN_MODULES[index];
        let record = &raw mut (*data).modules[index];
        if loaded & (1usize << index) == 0 || !(*record).entry.dll_base.is_null() {
            continue;
        }
        let full_name = b"C:\\Windows\\System32\\"
            .iter()
            .chain(name.as_bytes())
            .copied();
        let mut count = 0;
        for ch in full_name {
            (*record).name[count] = ch as u16;
            count += 1;
        }
        let name = UnicodeString::from_raw_parts(
            (&raw mut (*record).name).cast(),
            (2 * count) as u16,
            (2 * (count + 1)) as u16,
        );
        append_module(data, record, &Image::open(base)?, name, true);
    }
    Ok(())
}

unsafe fn loader_data() -> Result<*mut LoaderData, NtStatus> {
    let peb = nt_current_peb_address() as *mut Peb;
    if (*peb).ldr.is_null() {
        Err(STATUS_UNSUCCESSFUL)
    } else {
        Ok((*peb).ldr.cast())
    }
}

unsafe fn initialize() -> Result<usize, NtStatus> {
    let _lock = LoaderLock::acquire();
    let peb = nt_current_peb_address() as *mut Peb;
    let data = (peb as usize + LOADER_DATA_OFFSET) as *mut LoaderData;
    let image = Image::open((*peb).image_base_address as usize)?;
    let ntdll = module_index("ntdll.dll").ok_or(STATUS_UNSUCCESSFUL)?;
    let loaded = ensure_module(ntdll, 0)? | bind_imports(&image, 0, false)?;
    status_result(nt_syscall1(
        SYSCALL_PURENT_SEAL_IMAGE,
        CURRENT_EXECUTABLE_IMAGE,
    ))?;
    (*data).ldr.length = size_of::<PebLdrData>() as u32;
    ListEntry::initialize(&raw mut (*data).ldr.in_load_order_module_list);
    ListEntry::initialize(&raw mut (*data).ldr.in_memory_order_module_list);
    ListEntry::initialize(&raw mut (*data).ldr.in_initialization_order_module_list);
    let path = (*(*peb).process_parameters).image_path_name;
    append_module(data, &raw mut (*data).executable, &image, path, false);
    publish_modules(data, loaded)?;
    (*data).ldr.initialized = 1;
    (*peb).ldr = data.cast();
    Ok(image.entry)
}

unsafe extern "system" fn exit_process(status: u32) -> ! {
    nt_syscall2(0x29, u64::MAX, status as u64);
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "system" fn initial_entry() -> usize {
    match initialize() {
        Ok(entry) => entry,
        Err(status) => exit_process(status as u32),
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn PureNtLdrStart() -> ! {
    core::arch::naked_asm!(
        "sub rsp, 0x20",
        "call {initialize}",
        "call rax",
        "mov ecx, eax",
        "call {exit}",
        "ud2",
        initialize = sym initial_entry,
        exit = sym exit_process,
    );
}

unsafe fn name_index(name: *const UnicodeString) -> Result<usize, NtStatus> {
    let name = name.as_ref().ok_or(STATUS_INVALID_PARAMETER)?;
    if name.buffer.is_null() || name.length % 2 != 0 || name.length > 128 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut ascii = [0u8; 64];
    let len = name.length as usize / 2;
    for (i, byte) in ascii[..len].iter_mut().enumerate() {
        let unit = *name.buffer.add(i);
        if unit > 127 {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        *byte = unit as u8;
    }
    let name = core::str::from_utf8(&ascii[..len]).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    module_index(name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
}

#[no_mangle]
pub unsafe extern "system" fn LdrLoadDll(
    _path: *const u16,
    _characteristics: *const u32,
    name: *const UnicodeString,
    result: *mut usize,
) -> NtStatus {
    if result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    *result = 0;
    let _lock = LoaderLock::acquire();
    let loaded = (|| {
        let data = loader_data()?;
        let index = name_index(name)?;
        let modules = ensure_module(index, 0)?;
        publish_modules(data, modules)?;
        Ok(BUILTIN_MODULES[index].1)
    })();
    match loaded {
        Ok(base) => {
            *result = base;
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

#[no_mangle]
pub unsafe extern "system" fn LdrGetDllHandle(
    _path: *const u16,
    _characteristics: *const u32,
    name: *const UnicodeString,
    result: *mut usize,
) -> NtStatus {
    if result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    *result = 0;
    let _lock = LoaderLock::acquire();
    let base = (|| {
        let data = loader_data()?;
        let index = name_index(name)?;
        let base = (*data).modules[index].entry.dll_base as usize;
        if base == 0 {
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        } else {
            Ok(base)
        }
    })();
    match base {
        Ok(base) => {
            *result = base;
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

#[no_mangle]
pub unsafe extern "system" fn LdrGetProcedureAddress(
    base: usize,
    name: *const AnsiString,
    _ordinal: u32,
    result: *mut usize,
) -> NtStatus {
    if result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    *result = 0;
    let Some(name) = name.as_ref() else {
        return STATUS_NOT_SUPPORTED;
    };
    if name.buffer.is_null() || name.length == 0 || name.length > 256 {
        return STATUS_INVALID_PARAMETER;
    }
    let _lock = LoaderLock::acquire();
    let address = (|| {
        let data = loader_data()?;
        if (*data).executable.entry.dll_base as usize != base
            && !(&(*data).modules)
                .iter()
                .any(|record| record.entry.dll_base as usize == base && base != 0)
        {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let mut loaded = 0;
        let name = core::slice::from_raw_parts(name.buffer, name.length as usize);
        let address = resolve(&Image::open(base)?, name, 0, 0, &mut loaded)?;
        publish_modules(data, loaded)?;
        Ok(address)
    })();
    match address {
        Ok(address) => {
            *result = address;
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}
