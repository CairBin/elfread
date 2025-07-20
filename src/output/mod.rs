use crate::elf::header::SectionHeader;

use super::elf::ElfFile;
use super::elf::header::ProgramHeader;
use tabled::Tabled;

#[derive(Debug, Tabled)]
pub struct ElfHeaderTable {
    #[tabled(rename = "Magic")]
    magic: String,

    #[tabled(rename = "Class")]
    class: String,

    #[tabled(rename = "Data Encoding")]
    encoding: String,

    #[tabled(rename = "Version")]
    version: String,

    #[tabled(rename = "OS/ABI")]
    osabi: String,

    #[tabled(rename = "ABI Version")]
    abi_version: u8,

    #[tabled(rename = "Type")]
    tp: String,

    #[tabled(rename = "Machine")]
    machine: String,

    #[tabled(rename = "Entry Point")]
    entry_point: String,

    #[tabled(rename = "Program Header Offset")]
    pragram_header_offset: String,

    #[tabled(rename = "Section Header Offset")]
    section_header_offset: String,

    #[tabled(rename = "Flags")]
    flags: String,

    #[tabled(rename = "ELF Header Size")]
    elf_header_size: String,

    #[tabled(rename = "Program Header Entry Size")]
    ph_ensize: String,

    #[tabled(rename = "Program Header Entry Count")]
    ph_cnt: u16,

    #[tabled(rename = "Section Header Entry Size")]
    sh_ensize: String,

    #[tabled(rename = "Section Header Entry Count")]
    sh_cnt: u16,

    #[tabled(rename = "Section Header String Table Index")]
    shstrndx: u16,
}

impl ElfHeaderTable {
    pub fn from_elf_file(elf_file: &ElfFile) -> Self {
        Self {
            magic: format!("{:02X?}", &elf_file.e_ident[..4]),
            class: elf_file.get_class().to_string(),
            encoding: elf_file.get_data().to_string(),
            osabi: elf_file.get_osabi().to_string(),
            abi_version: elf_file.e_ident[7],
            tp: elf_file.get_type().to_string(),
            machine: elf_file.get_machine().to_string(),
            version: format!("0x{:X}", elf_file.e_version),
            entry_point: format!("0x{:X}", elf_file.e_entry),
            pragram_header_offset: format!("0x{:X}", elf_file.e_phoff),
            section_header_offset: format!("0x{:X}", elf_file.e_shoff),
            flags: format!("0x{:X}", elf_file.e_flags),
            elf_header_size: format!("{} bytes", elf_file.e_ehsize),
            ph_ensize: format!("0x{:X} bytes", elf_file.e_phentsize),
            ph_cnt: elf_file.e_phnum,
            sh_ensize: format!("0x{:X} bytes", elf_file.e_shentsize),
            sh_cnt: elf_file.e_shnum,
            shstrndx: elf_file.e_shstrndx,
        }
    }
}

#[derive(Debug, Tabled)]
pub struct ProgramHeaderTable {
    #[tabled(rename = "Index")]
    index: usize,

    #[tabled(rename = "Flags")]
    flags: String,

    #[tabled(rename = "Type")]
    tp: String,

    #[tabled(rename = "Offset")]
    offset: String,
}

#[derive(Debug, Tabled)]
pub struct ProgramHeaderTable2 {
    #[tabled(rename = "Index")]
    index: usize,
    #[tabled(rename = "Virtual Address")]
    vaddr: String,

    #[tabled(rename = "Physical Address")]
    paddr: String,

    #[tabled(rename = "File Size")]
    file_sz: String,

    #[tabled(rename = "Memory Size")]
    mem_sz: String,

    #[tabled(rename = "Alignment")]
    align: String,
}

impl ProgramHeaderTable2 {
    pub fn from_ph(ndx: usize, ph: &ProgramHeader) -> Self {
        match ph {
            ProgramHeader::Elf32(p) => Self {
                index: ndx,
                vaddr: format!("0x{:016X}", p.p_vaddr),
                paddr: format!("0x{:016X}", p.p_paddr),
                file_sz: format!("0x{:X}", p.p_filesz),
                mem_sz: format!("0x{:X}", p.p_memsz),
                align: format!("0x{:X}", p.p_align),
            },

            ProgramHeader::Elf64(p) => Self {
                index: ndx,
                vaddr: format!("0x{:016X}", p.p_vaddr),
                paddr: format!("0x{:016X}", p.p_paddr),
                file_sz: format!("0x{:X}", p.p_filesz),
                mem_sz: format!("0x{:X}", p.p_memsz),
                align: format!("0x{:X}", p.p_align),
            },
        }
    }
}

impl ProgramHeaderTable {
    pub fn from_ph(ndx: usize, ph: &ProgramHeader) -> Self {
        match ph {
            ProgramHeader::Elf32(p) => Self {
                index: ndx,
                tp: ph.get_type().to_string(),
                flags: ph.get_flags().to_string(),
                offset: format!("0x{:016X}", p.p_offset),
            },

            ProgramHeader::Elf64(p) => Self {
                index: ndx,
                tp: ph.get_type().to_string(),
                flags: ph.get_flags().to_string(),
                offset: format!("0x{:016X}", p.p_offset),
            },
        }
    }
}

#[derive(Debug, Tabled)]
pub struct SectionHeaderTable {
    #[tabled(rename = "Index")]
    index: usize,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    sh_type: String,
    #[tabled(rename = "Flags")]
    flags: String,
    #[tabled(rename = "Address")]
    addr: String,
}

#[derive(Debug, Tabled)]
pub struct SectionHeaderTable2 {
    #[tabled(rename = "Index")]
    index: usize,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Offset")]
    offset: String,
    #[tabled(rename = "Link")]
    link: u32,
    #[tabled(rename = "Info")]
    info: u32,
    #[tabled(rename = "AddrAlign")]
    addralign: String,
}

#[derive(Debug, Tabled)]
pub struct SectionHeaderTable3 {
    #[tabled(rename = "Index")]
    index: usize,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "EntSize")]
    entsize: String,
    #[tabled(rename = "Size")]
    size: String,
}

impl SectionHeaderTable {
    pub fn from_sh(ndx: usize, sh: &SectionHeader, elf_file: &ElfFile) -> Self {
        match sh {
            SectionHeader::Elf32(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    sh_type: sh.get_type().to_string(),
                    flags: sh.get_type().to_string(),
                    addr: format!("0x{:016X}", s.sh_addr),
                    
                }
            }

            SectionHeader::Elf64(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    sh_type: sh.get_type().to_string(),
                    flags: sh.get_type().to_string(),
                    addr: format!("0x{:016X}", s.sh_addr),
                }
            }
        }
    }
}


impl SectionHeaderTable2 {
    pub fn from_sh(ndx: usize, sh: &SectionHeader, elf_file: &ElfFile) -> Self {
        match sh {
            SectionHeader::Elf32(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    offset: format!("0x{:016X}", s.sh_offset),
                    link: s.sh_link,
                    info: s.sh_info,
                    addralign: format!("0x{:016X}", s.sh_addralign),
                }
            }

            SectionHeader::Elf64(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    offset: format!("0x{:016X}", s.sh_offset),
                    link: s.sh_link,
                    info: s.sh_info,
                    addralign: format!("0x{:016X}", s.sh_addralign),
                }
            }
        }
    }
}


impl SectionHeaderTable3 {
    pub fn from_sh(ndx: usize, sh: &SectionHeader, elf_file: &ElfFile) -> Self {
        match sh {
            SectionHeader::Elf32(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    entsize: format!("0x{:016X}", s.sh_entsize),
                    size: format!("0x{:016X}", s.sh_size),
                }
            }

            SectionHeader::Elf64(s) => {
                let name = match elf_file.get_section_name(ndx) {
                    Some(n) => n,
                    _ => String::new(),
                };

                Self {
                    index: ndx,
                    name: name,
                    entsize: format!("0x{:016X}", s.sh_entsize),
                    size: format!("0x{:016X}", s.sh_size),
                }
            }
        }
    }
}