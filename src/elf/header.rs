#[derive(Debug, Clone, Copy)]
pub struct Elf32Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader32 {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader32 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader64 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Debug)]
pub enum ProgramHeader {
    Elf32(ProgramHeader32),
    Elf64(ProgramHeader64),
}

#[derive(Debug)]
pub enum SectionHeader {
    Elf32(SectionHeader32),
    Elf64(SectionHeader64),
}

/*
pub struct ProgramHeader64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
} */

impl ProgramHeader {
    pub fn get_type(&self) -> &'static str {
        match self {
            ProgramHeader::Elf32(ph) => match ph.p_type {
                0 => "NULL",
                1 => "LOAD",
                2 => "DYNAMIC",
                3 => "INTERP",
                4 => "NOTE",
                5 => "SHLIB",
                6 => "PHDR",
                7 => "TLS",
                8 => "NUM",
                0x60000000 => "LOOS",
                0x60000001..=0x6FFFFFFF => "OS spec",
                0x70000000 => "LOPROC",
                0x70000001..=0x7FFFFFFF => "Processor spec)",
                _ => "Unknown",
            },

            ProgramHeader::Elf64(ph) => match ph.p_type {
                0 => "NULL",
                1 => "LOAD",
                2 => "DYNAMIC",
                3 => "INTERP",
                4 => "NOTE",
                5 => "SHLIB",
                6 => "PHDR",
                7 => "TLS",
                8 => "NUM",
                0x60000000 => "LOOS",
                0x60000001..=0x6FFFFFFF => "OS spec",
                0x70000000 => "LOPROC",
                0x70000001..=0x7FFFFFFF => "Processor spec)",
                _ => "Unknown",
            },
        }
    }

    pub fn get_flags(&self) -> String {
        match self {
            ProgramHeader::Elf32(ph) => {
                let mut flags = String::new();
                if ph.p_flags & 0x1 != 0 {
                    flags.push('X');
                } else {
                    flags.push('-');
                }
                if ph.p_flags & 0x2 != 0 {
                    flags.push('W');
                } else {
                    flags.push('-');
                }
                if ph.p_flags & 0x4 != 0 {
                    flags.push('R');
                } else {
                    flags.push('-');
                }
                flags
            }

            ProgramHeader::Elf64(ph) => {
                let mut flags = String::new();
                if ph.p_flags & 0x1 != 0 {
                    flags.push('X');
                } else {
                    flags.push('-');
                }
                if ph.p_flags & 0x2 != 0 {
                    flags.push('W');
                } else {
                    flags.push('-');
                }
                if ph.p_flags & 0x4 != 0 {
                    flags.push('R');
                } else {
                    flags.push('-');
                }
                flags
            }
        }
    }
}

impl SectionHeader {
    pub fn get_type(&self) -> &'static str {
        match self {
            SectionHeader::Elf32(sh) => match sh.sh_type {
                0 => "NULL",
                1 => "PROGBITS",
                2 => "SYMTAB",
                3 => "STRTAB",
                4 => "RELA",
                5 => "HASH",
                6 => "DYNAMIC",
                7 => "NOTE",
                8 => "NOBITS",
                9 => "REL",
                10 => "SHLIB",
                11 => "DYNSYM",
                14 => "INIT_ARRAY",
                15 => "FINI_ARRAY",
                16 => "PREINIT_ARRAY",
                17 => "GROUP",
                18 => "SYMTAB_SHNDX",
                19 => "RELR",
                20 => "NUM",
                0x60000000 => "LOOS",
                0x60000001..=0x6FFFFFFF => "OS spec",
                0x70000000 => "LOPROC",
                0x70000001..=0x7FFFFFFF => "Processor spec",
                _ => "Unknown",
            },
            SectionHeader::Elf64(sh) => match sh.sh_type {
                0 => "NULL",
                1 => "PROGBITS",
                2 => "SYMTAB",
                3 => "STRTAB",
                4 => "RELA",
                5 => "HASH",
                6 => "DYNAMIC",
                7 => "NOTE",
                8 => "NOBITS",
                9 => "REL",
                10 => "SHLIB",
                11 => "DYNSYM",
                14 => "INIT_ARRAY",
                15 => "FINI_ARRAY",
                16 => "PREINIT_ARRAY",
                17 => "GROUP",
                18 => "SYMTAB_SHNDX",
                19 => "RELR",
                20 => "NUM",
                0x60000000 => "LOOS",
                0x60000001..=0x6FFFFFFF => "OS spec",
                0x70000000 => "LOPROC",
                0x70000001..=0x7FFFFFFF => "Processor spec",
                _ => "Unknown",
            },
        }
    }
}
