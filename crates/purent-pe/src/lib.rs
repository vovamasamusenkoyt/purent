#![no_std]

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[derive(Debug)]
pub enum PeError {
    BufferTooSmall,
    InvalidDosSignature,
    InvalidNtSignature,
    InvalidMachine,
    InvalidOptionalHeader,
    InvalidSection,
}

pub struct PeView<'a> {
    data: &'a [u8],
    nt_headers_offset: usize,
}

impl<'a> PeView<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        if data.len() < core::mem::size_of::<ImageDosHeader>() {
            return Err(PeError::BufferTooSmall);
        }

        let dos = unsafe { &*(data.as_ptr() as *const ImageDosHeader) };
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosSignature);
        }

        let nt_offset = dos.e_lfanew as usize;
        if data.len() < nt_offset + core::mem::size_of::<ImageNtHeaders64>() {
            return Err(PeError::BufferTooSmall);
        }

        let nt = unsafe { &*(data.as_ptr().add(nt_offset) as *const ImageNtHeaders64) };
        if nt.signature != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidNtSignature);
        }

        if nt.file_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::InvalidMachine);
        }

        if nt.optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::InvalidOptionalHeader);
        }

        Ok(Self {
            data,
            nt_headers_offset: nt_offset,
        })
    }

    pub fn nt_headers(&self) -> &ImageNtHeaders64 {
        unsafe { &*(self.data.as_ptr().add(self.nt_headers_offset) as *const ImageNtHeaders64) }
    }

    pub fn entry_point_rva(&self) -> u32 {
        self.nt_headers().optional_header.address_of_entry_point
    }

    pub fn image_base(&self) -> u64 {
        self.nt_headers().optional_header.image_base
    }

    pub fn size_of_image(&self) -> u32 {
        self.nt_headers().optional_header.size_of_image
    }

    pub fn section_headers(&self) -> &[ImageSectionHeader] {
        let nt = self.nt_headers();
        let num_sections = nt.file_header.number_of_sections as usize;
        let opt_size = nt.file_header.size_of_optional_header as usize;
        let sections_offset = self.nt_headers_offset
            + 4 // signature
            + core::mem::size_of::<ImageFileHeader>()
            + opt_size;

        unsafe {
            let ptr = self.data.as_ptr().add(sections_offset) as *const ImageSectionHeader;
            core::slice::from_raw_parts(ptr, num_sections)
        }
    }

    pub fn data_directory(&self, idx: usize) -> Option<&ImageDataDirectory> {
        let nt = self.nt_headers();
        if idx < nt.optional_header.number_of_rva_and_sizes as usize {
            Some(&nt.optional_header.data_directory[idx])
        } else {
            None
        }
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in self.section_headers() {
            let va = sec.virtual_address;
            let vsize = sec.virtual_size;
            let rsize = sec.size_of_raw_data;
            let span = if vsize > rsize { vsize } else { rsize };
            if rva >= va && rva < va + span {
                let delta = (rva - va) as usize;
                return Some(sec.pointer_to_raw_data as usize + delta);
            }
        }
        None
    }
}
