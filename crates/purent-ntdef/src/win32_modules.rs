//! Preferred addresses of the built-in compatibility DLLs.

pub const BUILTIN_MODULES: &[(&str, usize)] = &[
    ("kernel32.dll", 0x7000_0000),
    ("user32.dll", 0x7100_0000),
    ("shell32.dll", 0x7200_0000),
    ("ntdll.dll", 0x7300_0000),
    ("msvcrt.dll", 0x7400_0000),
    ("winbrand.dll", 0x7500_0000),
    ("kernelbase.dll", 0x7600_0000),
];

pub const LIBRARY_LOADER_API_SET: &str = "api-ms-win-core-libraryloader-l1-1-0.dll";

/// The library-loader API set is implemented by KernelBase on Windows 7.
pub fn module_import_host(name: &str) -> &str {
    if module_name_matches(LIBRARY_LOADER_API_SET, name) {
        "kernelbase.dll"
    } else {
        name
    }
}

pub fn module_name_matches(module: &str, requested: &str) -> bool {
    module.eq_ignore_ascii_case(requested)
        || module.strip_suffix(".dll").is_some_and(|name| name.eq_ignore_ascii_case(requested))
}
