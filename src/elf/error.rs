use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElfError{
    #[error("Invalid elf file")]
    InvalidMagic,
    
    #[error("Unsupported ELF class: {0}")]
    UnsupportedClass(u8),

    #[error("Unsupported data format: {0}")]
    UnsupportedData(u8),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported ELF ABI: {0}")]
    UnsupportedAbi(u8),

    #[error("Unsupported ELF type: {0}")]
    UnsupportedType(u16),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}
