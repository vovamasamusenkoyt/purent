//! Minimal ELF64 loader for purentoskrnl

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Elf64Header {
    pub ident: [u8; 16],
    pub r#type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Elf64ProgramHeader {
    pub r#type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

pub const PT_LOAD: u32 = 1;

pub struct Elf64View<'a> {
    data: &'a [u8],
}

impl<'a> Elf64View<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < core::mem::size_of::<Elf64Header>() {
            return Err("Buffer too small for ELF header");
        }
        let hdr = unsafe { &*(data.as_ptr() as *const Elf64Header) };
        if &hdr.ident[0..4] != b"\x7FELF" {
            return Err("Invalid ELF magic");
        }
        if hdr.ident[4] != 2 {
            return Err("Not 64-bit ELF");
        }
        if hdr.machine != 0x3E {
            // x86_64
            return Err("Not x86_64 ELF");
        }
        Ok(Self { data })
    }

    pub fn header(&self) -> &Elf64Header {
        unsafe { &*(self.data.as_ptr() as *const Elf64Header) }
    }

    pub fn entry_point(&self) -> u64 {
        self.header().entry
    }

    pub fn program_headers(&self) -> &[Elf64ProgramHeader] {
        let hdr = self.header();
        let offset = hdr.phoff as usize;
        let count = hdr.phnum as usize;
        unsafe {
            let ptr = self.data.as_ptr().add(offset) as *const Elf64ProgramHeader;
            core::slice::from_raw_parts(ptr, count)
        }
    }
}
