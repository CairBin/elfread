mod elf;
mod output;

use clap::Parser;
use elf::ElfFile;
use owo_colors::OwoColorize;
use std::fs;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use tabled::{Table, settings::Style};

use crate::output::{
    ProgramHeaderTable, ProgramHeaderTable2, SectionHeaderTable, SectionHeaderTable2
};

#[derive(Debug, Parser)]
#[command(version, about, long_about = "A tool for parsing ELF32/64 files.")]
struct Usage {
    file: Option<PathBuf>,

    #[arg(short, long, help = "Print program header information")]
    program: bool,

    #[arg(short, long, help = "Print section header information")]
    section: bool,

    #[arg(short, long, help = "Print all information")]
    all: bool,
}

fn print_brief(elf_file: &ElfFile) {
    println!("\n--------------------------------------------------");
    println!(
        "-------------- {} --------------",
        "ELF File Information".green()
    );

    println!("  Magic: {:02X?}", &elf_file.e_ident[..4]);
    println!("  Class: {}", elf_file.get_class());
    println!("  Data Encoding: {}", elf_file.get_data());
    println!("  Version: {}", elf_file.e_version);
    println!("  OS/ABI: {}", elf_file.get_osabi());
    println!("  ABI Version: {}", elf_file.e_ident[7]);
    println!("  Type: {}", elf_file.get_type());
    println!("  Machine: {}", elf_file.get_machine());
    println!("  Version: 0x{:X}", elf_file.e_version);
    println!("  Entry Point: 0x{:X}", elf_file.e_entry);
    println!("  Program Header Offset: 0x{:X}", elf_file.e_phoff);
    println!("  Section Header Offset: 0x{:X}", elf_file.e_shoff);
    println!("  Flags: 0x{:X}", elf_file.e_flags);
    println!("  ELF Header Size: {} bytes", elf_file.e_ehsize);
    println!(
        "  Program Header Entry Size: {} bytes",
        elf_file.e_phentsize
    );
    println!("  Program Header Entries: {}", elf_file.e_phnum);
    println!(
        "  Section Header Entry Size: {} bytes",
        elf_file.e_shentsize
    );
    println!("  Section Header Entries: {}", elf_file.e_shnum);
    println!(
        "  Section Header String Table Index: {}",
        elf_file.e_shstrndx
    );

    println!("--------------------------------------------------");
    println!("--------------------------------------------------\n");
}

fn print_section(elf_file: &ElfFile) {
    if !elf_file.section_headers.is_empty() {
        println!(
            "\n{}",
            ">>>>>>>>>>>>>>>>>>>>>>>>>>> Section Header Tables <<<<<<<<<<<<<<<<<<<<<<<<".green()
        );
        let shs = elf_file
            .section_headers
            .iter()
            .enumerate()
            .map(|(i, sh)| SectionHeaderTable::from_sh(i, &sh, &elf_file));
        let shs2 = elf_file
            .section_headers
            .iter()
            .enumerate()
            .map(|(i, sh)| SectionHeaderTable2::from_sh(i, &sh, &elf_file));
        let mut sh_table = Table::new(shs);
        sh_table.with(Style::modern());

        let mut sh_table2 = Table::new(shs2);
        sh_table2.with(Style::modern());


        println!("\n{}", "Section Header Info Table1:".green());
        println!("{}", sh_table);
        /*
            Key to Flags:
            W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
            L (link order), O (extra OS processing required), G (group), T (TLS),
            C (compressed), x (unknown), o (OS specific), E (exclude),
            D (mbind), p (processor specific)
        */
        println!("Key to Flags:");
        println!("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),");
        println!("  L (link order), O (extra OS processing required), G (group), T (TLS),");
        println!("  C (compressed), x (unknown), o (OS specific), E (exclude),");
        println!("  D (mbind), p (processor specific), - (empty)");

        println!("\n{}", "Section Header Info Table2:".green());
        println!("{}", sh_table2);
    }
}

fn print_program(elf_file: &ElfFile) {
    if !elf_file.program_headers.is_empty() {
        println!(
            "\n{}",
            ">>>>>>>>>>> Program Header Tables <<<<<<<<<<<".green()
        );
        let phs = elf_file
            .program_headers
            .iter()
            .enumerate()
            .map(|(i, ph)| ProgramHeaderTable::from_ph(i, &ph));
        let phs2 = elf_file
            .program_headers
            .iter()
            .enumerate()
            .map(|(i, ph)| ProgramHeaderTable2::from_ph(i, &ph));
        let mut ph_table = Table::new(phs);
        ph_table.with(Style::modern());

        let mut ph_table2 = Table::new(phs2);
        ph_table2.with(Style::modern());

        println!("\n{}", "Program Header Info Table1:".green());
        println!("{}", ph_table);
        
        println!("\n{}", "Program Header Info Table2:".green());
        println!("{}", ph_table2);
    }
}

fn main() {
    let cli = Usage::parse();
    if cli.file.is_none() {
        eprintln!("{}", "Error: the parsed file must be specified.".red());
        return;
    }
    let path_buf = cli.file.unwrap();
    let file = fs::File::open(path_buf);
    if file.is_err() {
        eprintln!(
            "{}",
            format!("{}", elf::error::ElfError::IoError(file.unwrap_err()).red())
        );
        return;
    }

    let mut buffer = Vec::new();
    let mut reader = BufReader::new(file.unwrap());
    let temp_res = reader.read_to_end(&mut buffer);
    if temp_res.is_err() {
        eprintln!(
            "{}",
            format!(
                "{}",
                elf::error::ElfError::IoError(temp_res.unwrap_err()).red()
            )
        );
        return;
    }

    // output content
    let elf_file = ElfFile::from_bytes(&buffer);
    if elf_file.is_err() {
        eprintln!("{}", format!("{}", elf_file.unwrap_err()).red());
        return;
    }
    let elf_file = elf_file.unwrap();

    if cli.all {
        print_brief(&elf_file);
        print_program(&elf_file);
        print_section(&elf_file);
        return;
    }

    if !cli.section && !cli.program {
        print_brief(&elf_file);
        return;
    }

    if cli.program {
        print_program(&elf_file);
    }

    if cli.section {
        print_section(&elf_file);
    }
}
