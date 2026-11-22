//! Bootloader Parameter Block passed from purent-boot to purentoskrnl

pub const PURENT_LOADER_MAGIC: u64 = 0x505552454E544C44; // "PURENTLD"

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MemoryDescriptor {
    pub r#type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FramebufferInfo {
    pub base_address: u64,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub pixels_per_scan_line: u32,
    pub pixel_format: u32, // 0: RGB, 1: BGR
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PureNtLoaderBlock {
    pub magic: u64,
    pub version: u32,
    pub flags: u32,

    pub kernel_physical_base: u64,
    pub kernel_virtual_base: u64,
    pub kernel_size: u64,

    pub cr3_pml4: u64,
    pub acpi_rsdp: u64,

    pub memory_map_addr: u64,
    pub memory_map_entries: u64,
    pub memory_map_desc_size: u64,

    pub framebuffer: FramebufferInfo,

    pub command_line: [u8; 256],
}

impl Default for PureNtLoaderBlock {
    fn default() -> Self {
        Self {
            magic: PURENT_LOADER_MAGIC,
            version: 1,
            flags: 0,
            kernel_physical_base: 0,
            kernel_virtual_base: 0,
            kernel_size: 0,
            cr3_pml4: 0,
            acpi_rsdp: 0,
            memory_map_addr: 0,
            memory_map_entries: 0,
            memory_map_desc_size: 0,
            framebuffer: FramebufferInfo {
                base_address: 0,
                size: 0,
                width: 0,
                height: 0,
                pixels_per_scan_line: 0,
                pixel_format: 0,
            },
            command_line: [0; 256],
        }
    }
}
