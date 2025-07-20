pub mod error;
pub mod header;

type Result<T> = std::result::Result<T, error::ElfError>;

#[derive(Debug)]
pub struct ElfFile {
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
    pub program_headers: Vec<header::ProgramHeader>,
    pub section_headers: Vec<header::SectionHeader>,
    pub data: Vec<u8>,
}

impl ElfFile {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // magic number
        if &data[0..4] != b"\x7FELF" {
            return Err(error::ElfError::InvalidMagic);
        }

        let mut e_ident = [0u8; 16];
        e_ident.copy_from_slice(&data[0..16]);

        let elf_class = e_ident[4];
        let elf_data = e_ident[5];
        let elf_version = e_ident[6];
        let elf_osabi = e_ident[7];
        let elf_abiversion = e_ident[8];

        // check elf class
        if elf_class != 1 && elf_class != 2 {
            // elf is not elf32 or elf64
            return Err(error::ElfError::UnsupportedClass(elf_class));
        }

        // check big end or small end
        if elf_data != 1 && elf_data != 2 {
            return Err(error::ElfError::UnsupportedData(elf_data));
        }

        if elf_version != 1 {
            return Err(error::ElfError::UnsupportedVersion(elf_version));
        }

        let elf_file = if elf_class == 1 {
            let reader = &mut std::io::Cursor::new(&data[16..]);
            let e_type = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_machine = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_version = byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)?;
            let e_entry =
                byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)? as u64;
            let e_phoff =
                byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)? as u64;
            let e_shoff =
                byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)? as u64;
            let e_flags = byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)?;
            let e_ehsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_phentsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_phnum = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shentsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shnum = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shstrndx = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;

            // parse program header
            let mut program_headers = Vec::new();
            for i in 0..e_phnum {
                let offset = (e_phoff + (i as u64 * e_phentsize as u64)) as usize;
                if offset + 32 > data.len() {
                    return Err(error::ElfError::ParseError(
                        "program header exceeds file range".to_string(),
                    ));
                }

                let ph_reader = &mut std::io::Cursor::new(&data[offset..offset + 32]);
                let p_type =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_offset =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_vaddr =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_paddr =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_filesz =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_memsz =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_flags =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_align =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;

                program_headers.push(header::ProgramHeader::Elf32(header::ProgramHeader32 {
                    p_type,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                }));
            }

            // parse section header
            let mut section_headers = Vec::new();
            for i in 0..e_shnum {
                let offset = (e_shoff + (i as u64 * e_shentsize as u64)) as usize;
                if offset + 40 > data.len() {
                    return Err(error::ElfError::ParseError(
                        "section header exceeds file range.".to_string(),
                    ));
                }

                let sh_reader = &mut std::io::Cursor::new(&data[offset..offset + 40]);
                let sh_name =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_type =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_flags =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_addr =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_offset =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_size =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_link =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_info =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_addralign =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_entsize =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;

                section_headers.push(header::SectionHeader::Elf32(header::SectionHeader32 {
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                }));
            }

            // return ElfFile
            ElfFile {
                e_ident,
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
                program_headers,
                section_headers,
                data: data.to_vec(),
            }
        } else {
            // parse elf64
            let reader = &mut std::io::Cursor::new(&data[16..]);
            let e_type = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_machine = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_version = byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)?;
            let e_entry = byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(reader)?;
            let e_phoff = byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(reader)?;
            let e_shoff = byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(reader)?;
            let e_flags = byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(reader)?;
            let e_ehsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_phentsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_phnum = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shentsize = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shnum = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;
            let e_shstrndx = byteorder::ReadBytesExt::read_u16::<byteorder::LittleEndian>(reader)?;

            // program header
            let mut program_headers = Vec::new();
            for i in 0..e_phnum {
                let offset = (e_phoff + (i as u64 * e_phentsize as u64)) as usize;
                if offset + 56 > data.len() {
                    return Err(error::ElfError::ParseError(
                        "program header exceeds file range.".to_string(),
                    ));
                }

                let ph_reader = &mut std::io::Cursor::new(&data[offset..offset + 56]);
                let p_type =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_flags =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(ph_reader)?;
                let p_offset =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;
                let p_vaddr =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;
                let p_paddr =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;
                let p_filesz =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;
                let p_memsz =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;
                let p_align =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(ph_reader)?;

                program_headers.push(header::ProgramHeader::Elf64(header::ProgramHeader64 {
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_align,
                }));
            }

            // section header
            let mut section_headers = Vec::new();
            for i in 0..e_shnum {
                let offset = (e_shoff + (i as u64 * e_shentsize as u64)) as usize;
                if offset + 64 > data.len() {
                    return Err(error::ElfError::ParseError(
                        "section header exceeds file range.".to_string(),
                    ));
                }

                let sh_reader = &mut std::io::Cursor::new(&data[offset..offset + 64]);
                let sh_name =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_type =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_flags =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;
                let sh_addr =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;
                let sh_offset =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;
                let sh_size =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;
                let sh_link =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_info =
                    byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(sh_reader)?;
                let sh_addralign =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;
                let sh_entsize =
                    byteorder::ReadBytesExt::read_u64::<byteorder::LittleEndian>(sh_reader)?;

                section_headers.push(header::SectionHeader::Elf64(header::SectionHeader64 {
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                }));
            }

            ElfFile {
                e_ident,
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
                program_headers,
                section_headers,
                data: data.to_vec(),
            }
        };

        Ok(elf_file)
    }

    pub fn get_class(&self) -> &'static str {
        match self.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "Unknown",
        }
    }

    pub fn get_data(&self) -> &'static str {
        match self.e_ident[5] {
            1 => "Little Endian",
            2 => "Big Endian",
            _ => "Unknown",
        }
    }

    pub fn get_osabi(&self) -> &'static str {
        match self.e_ident[7] {
            0 => "System V",
            1 => "HP-UX",
            2 => "NetBSD",
            3 => "GNU/Linux",
            6 => "Solaris",
            7 => "AIX",
            8 => "IRIX",
            9 => "FreeBSD",
            10 => "Tru64",
            11 => "Novell Modesto",
            12 => "OpenBSD",
            13 => "OpenVMS",
            14 => "NonStop Kernel",
            15 => "AROS",
            16 => "Fenix OS",
            17 => "CloudABI",
            18 => "Stratus Technologies OpenVOS",
            64 => "ARM EABI",
            97 => "ARM",
            _ => "Unknown",
        }
    }

    pub fn get_type(&self) -> &'static str {
        match self.e_type {
            0 => "None",
            1 => "Relocatable",
            2 => "Executable",
            3 => "Shared",
            4 => "Core",
            0xFF00..=0xFFFF => "Processor-specific",
            _ => "Unknown",
        }
    }

    pub fn get_machine(&self) -> &'static str {
        match self.e_machine {
            0 => "None",
            1 => "M32",
            2 => "SPARC",
            3 => "Intel 80386",
            4 => "Motorola 68K",
            5 => "Motorola 88K",
            6 => "Intel MCU",
            7 => "Intel 80860",
            8 => "MIPS",
            9 => "S370",
            10=>"MIPS RS3 LE",
            15=> "PA-RISC",
            17=> "VPP500",
            18=> "SPARC32 Plus",
            19=>"Intel 80960",
            20 => "PowerPC",
            21 => "PowerPC64",
            22 => "IBM S/390",
            23=>"IBM SPU",
            40 => "ARM",
            42 => "SuperH",
            43 => "SparcV9",
            44 => "Tricore",
            45 => "ARC",
            46 => "H8/300",
            47=>"H8/300H",
            48=>"H8S",
            49=>"H8/500",
            50 => "IA-64",
            51 => "MIPS-X",
            52 => "Coldfire",
            53 => "M68HC12",
            54 => "MMA",
            55 => "PCP",
            56 => "Sony nCPU",
            57 => "Denso NDR1",
            58 => "Start*Core",
            59 => "ME16",
            60=>"ST100",
            61 => "Tinyj",
            62 => "x86-64",
            63 => "PDSP",
            64 => "PDP-10",
            65 => "PDP-11",
            66 => "FX66",
            67 => "ST9+",
            68 => "ST7",
            69 => "MC68HC16",
            70 => "MC68HC11",
            71 => "MC68HC08",
            72 => "MC68HC05",
            73 => "SVx",
            74 => "ST19",
            75 => "VAX",
            76 => "CRIS",

            183 => "AArch64",
            224=>"AMD GPU",
            243 => "RISC-V",
            258 => "LoongArch",
            _ => "Unknown",
        }
    }

    pub fn get_section_name(&self, index: usize) -> Option<String> {
        if index >= self.section_headers.len()
            || self.e_shstrndx >= self.section_headers.len() as u16
        {
            return None;
        }

        let shstrtab = match &self.section_headers[self.e_shstrndx as usize] {
            header::SectionHeader::Elf32(sh) => {
                &self.data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize]
            }
            header::SectionHeader::Elf64(sh) => {
                &self.data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize]
            }
        };

        let name_offset = match &self.section_headers[index] {
            header::SectionHeader::Elf32(sh) => sh.sh_name as usize,
            header::SectionHeader::Elf64(sh) => sh.sh_name as usize,
        };

        if name_offset >= shstrtab.len() {
            return None;
        }

        // find '\0'
        let end = shstrtab[name_offset..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(shstrtab.len() - name_offset);
        String::from_utf8(shstrtab[name_offset..name_offset + end].to_vec()).ok()
    }
}
