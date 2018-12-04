//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

extern crate elfkit;
// extern crate enum_primitive_derive;
extern crate num_traits;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use ebpf;
use elf::num_traits::FromPrimitive;
use std::io::Cursor;
use std::io::{Error, ErrorKind};

// For more information on the BPF instruction set:
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

const BYTE_OFFSET_IMMEDIATE: usize = 4;
const BYTE_LENGTH_IMMEIDATE: usize = 4;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BPFRelocationType {
    /// none none
    R_BPF_NONE = 0,
    /// word64 S + A
    R_BPF_64_64 = 1,
    /// wordclass B + A
    R_BPF_64_RELATIVE = 8,
    /// word32 S + A
    R_BPF_64_32 = 10,
}

impl BPFRelocationType {
    fn from_x86_relocation_type(
        from: &elfkit::relocation::RelocationType,
    ) -> Option<BPFRelocationType> {
        match *from {
            elfkit::relocation::RelocationType::R_X86_64_NONE => {
                Some(BPFRelocationType::R_BPF_NONE)
            }
            elfkit::relocation::RelocationType::R_X86_64_64 => Some(BPFRelocationType::R_BPF_64_64),
            elfkit::relocation::RelocationType::R_X86_64_RELATIVE => {
                Some(BPFRelocationType::R_BPF_64_RELATIVE)
            }
            elfkit::relocation::RelocationType::R_X86_64_32 => Some(BPFRelocationType::R_BPF_64_32),
            _ => None,
        }
    }
}

/// Elf loader/relocator
pub struct EBpfElf {
    /// Elf representation
    elf: elfkit::Elf,
}

impl EBpfElf {
    /// Fully loads an ELF, including validation and relocation
    pub fn load(elf_bytes: &[u8]) -> Result<(EBpfElf), Error> {
        let mut reader = Cursor::new(elf_bytes);
        let mut elf = match elfkit::Elf::from_reader(&mut reader) {
            Ok(elf) => elf,
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("Error: Failed to parse elf: {:?}", e),
            ))?,
        };
        if let Err(e) = elf.load_all(&mut reader) {
            Err(Error::new(
                ErrorKind::Other,
                format!("Error: Failed to parse elf: {:?}", e),
            ))?;
        }
        let mut ebpf_elf = EBpfElf { elf };
        ebpf_elf.validate()?;
        ebpf_elf.relocate()?;
        Ok(ebpf_elf)
    }

    /// Gets the .text section
    pub fn get_text_section(&self) -> Result<&[u8], Error> {
        Ok(match self
            .elf
            .sections
            .iter()
            .find(|section| section.name == b".text")
        {
            Some(section) => match section.content {
                elfkit::SectionContent::Raw(ref bytes) => {
                    if bytes.is_empty() {
                        return Err(Error::new(ErrorKind::Other, "Error: Empty .text section"))?;
                    } else {
                        bytes
                    }
                }
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .text contents",
                ))?,
            },
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .text section found",
            ))?,
        })
    }

    /// Get a vector of read-only data sections
    pub fn get_rodata<'a>(&'a self) -> Result<Vec<&'a [u8]>, Error> {
        let rodata: Result<Vec<_>, _> = self
            .elf
            .sections
            .iter()
            .filter(|section| section.name.starts_with(b".rodata"))
            .map(EBpfElf::content_to_bytes)
            .collect();
        if let Ok(ref v) = rodata {
            if v.is_empty() {
                Err(Error::new(ErrorKind::Other, "Error: No RO data"))?;
            }
        }
        rodata
    }

    /// Converts a section's raw contents to a slice
    fn content_to_bytes(section: &elfkit::section::Section) -> Result<&[u8], Error> {
        match section.content {
            elfkit::SectionContent::Raw(ref bytes) => Ok(bytes),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .rodata contents",
            )),
        }
    }

    /// Validates the ELF
    fn validate(&self) -> Result<(), Error> {
        // Validate header
        if self.elf.header.ident_class != elfkit::types::Class::Class64 {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong class",
            ));
        }
        if self.elf.header.ident_endianness != elfkit::types::Endianness::LittleEndian {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong endianess",
            ));
        }
        if self.elf.header.ident_abi != elfkit::types::Abi::SYSV {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong abi",
            ));
        }
        if self.elf.header.machine != elfkit::types::Machine::BPF {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong machine",
            ));
        }
        if self.elf.header.etype != elfkit::types::ElfType::DYN {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Incompatible ELF: wrong type",
            ));
        }

        let text_sections: Vec<_> = self
            .elf
            .sections
            .iter()
            .filter(|section| section.name.starts_with(b".text"))
            .collect();
        if text_sections.len() > 1 {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: Multiple text sections, consider removing llc option: -function-sections",
            ));
        }

        Ok(())
    }

    /// Performs relocation on the text section
    fn relocate(&mut self) -> Result<(), Error> {
        let text_bytes = {
            let raw_relocation_bytes = match self
                .elf
                .sections
                .iter()
                .find(|section| section.name.starts_with(b".rel.dyn"))
            {
                Some(section) => match section.content {
                    elfkit::SectionContent::Raw(ref bytes) => bytes.clone(),
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Failed to get .rel.dyn contents",
                    ))?,
                },
                None => return Ok(()), // no relocation section, no need to relocate
            };
            let relocations = EBpfElf::get_relocations(&raw_relocation_bytes[..])?;

            let (mut text_bytes, text_va) = match self
                .elf
                .sections
                .iter()
                .find(|section| section.name.starts_with(b".text"))
            {
                Some(section) => (
                    match section.content {
                        elfkit::SectionContent::Raw(ref bytes) => bytes.clone(),
                        _ => Err(Error::new(
                            ErrorKind::Other,
                            "Error: Failed to get .text contents",
                        ))?,
                    },
                    section.header.addr,
                ),
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: No .text section found",
                ))?,
            };

            let rodata_section = match self
                .elf
                .sections
                .iter()
                .find(|section| section.name.starts_with(b".rodata"))
            {
                Some(section) => section,
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: No .rodata section found",
                ))?,
            };

            let symbols = match self
                .elf
                .sections
                .iter()
                .find(|section| section.name.starts_with(b".dynsym"))
            {
                Some(section) => match section.content {
                    elfkit::SectionContent::Symbols(ref bytes) => bytes.clone(),
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Failed to get .symtab contents",
                    ))?,
                },
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: No .symtab section found",
                ))?,
            };

            for relocation in relocations.iter() {
                match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                    Some(BPFRelocationType::R_BPF_64_RELATIVE) => {
                        // The .text section has a reference to a symbol in the .rodata section

                        // Offset of the instruction in the text section being relocated
                        let mut imm_offset =
                            (relocation.addr - text_va) as usize + BYTE_OFFSET_IMMEDIATE;
                        // Read the instruction's immediate field which contains the rodata symbol's virtual address
                        let ro_va = LittleEndian::read_u32(
                            &text_bytes[imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                        ) as u64;
                        // Convert into an offset into the rodata section by subtracting the rodata section's base virtual address
                        let ro_offset = ro_va - rodata_section.header.addr;
                        // Get the rodata's physical address
                        let rodata_pa = match rodata_section.content {
                            elfkit::SectionContent::Raw(ref raw) => raw,
                            _ => Err(Error::new(
                                ErrorKind::Other,
                                "Error: Failed to get .rodata contents",
                            ))?,
                        }.as_ptr() as u64;
                        // Calculator the symbol's physical address within the rodata section
                        let symbol_addr = rodata_pa + ro_offset;

                        // Instruction lddw spans two instruction slots, split
                        // symbol's address into two and write into both
                        // slot's imm field
                        let imm_length = 4;
                        LittleEndian::write_u32(
                            &mut text_bytes[imm_offset..imm_offset + imm_length],
                            (symbol_addr & 0xFFFFFFFF) as u32,
                        );
                        imm_offset += ebpf::INSN_SIZE;
                        LittleEndian::write_u32(
                            &mut text_bytes[imm_offset..imm_offset + imm_length],
                            (symbol_addr >> 32) as u32,
                        );
                    }
                    Some(BPFRelocationType::R_BPF_64_32) => {
                        // The .text section has an unresolved call instruction
                        //
                        // Hash the symbol name and stick it into the call
                        // instruction's imm field.  Later  that hash will be
                        // used to look up the actual helper.

                        let name = &symbols[relocation.sym as usize].name;
                        let imm_offset =
                            (relocation.addr - text_va) as usize + BYTE_OFFSET_IMMEDIATE;
                        LittleEndian::write_u32(
                            &mut text_bytes[imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                            ebpf::hash_symbol_name(name),
                        );
                    }
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Unhandled relocation type",
                    ))?,
                }
            }
            text_bytes
        };

        // Write back fixed-up text section
        let mut text_section = match self
            .elf
            .sections
            .iter_mut()
            .find(|section| section.name.starts_with(b".text"))
        {
            Some(section) => &mut section.content,
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .text section found",
            ))?,
        };

        *text_section = elfkit::SectionContent::Raw(text_bytes.to_vec());

        Ok(())
    }

    /// Builds a vector of Relocations from raw bytes
    ///
    /// Elfkit does not form BPF relocations and instead just provides
    /// raw bytes
    fn get_relocations<R>(mut io: R) -> Result<Vec<elfkit::Relocation>, Error>
    where
        R: std::io::Read,
    {
        let mut relocs = Vec::new();

        while let Ok(addr) = io.read_u64::<LittleEndian>() {
            let info = match io.read_u64::<LittleEndian>() {
                Ok(v) => v,
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to read relocation info",
                ))?,
            };

            let sym = (info >> 32) as u32;
            let rtype = (info & 0xffffffff) as u32;
            let rtype = match elfkit::relocation::RelocationType::from_u32(rtype) {
                Some(v) => v,
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Error: unknown relocation type",
                ))?,
            };

            let addend = 0; // BPF relocation don't have an addend

            relocs.push(elfkit::relocation::Relocation {
                addr,
                sym,
                rtype,
                addend,
            });
        }

        Ok(relocs)
    }

    #[allow(dead_code)]
    fn dump_data(name: &str, prog: &[u8]) {
        let mut eight_bytes: Vec<u8> = Vec::new();
        println!("{}", name);
        for i in prog.iter() {
            if eight_bytes.len() >= 7 {
                println!("{:02X?}", eight_bytes);
                eight_bytes.clear();
            } else {
                eight_bytes.push(i.clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_validate() {
        let mut file = File::open("tests/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).unwrap();

        elf.validate().expect("validation failed");
        elf.elf.header.ident_class = elfkit::types::Class::Class32;
        elf.validate().expect_err("allowed bad class");
        elf.elf.header.ident_class = elfkit::types::Class::Class64;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::BigEndian;
        elf.validate().expect_err("allowed big endian");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::LittleEndian;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_abi = elfkit::types::Abi::ARM;
        elf.validate().expect_err("allowed wrong abi");
        elf.elf.header.ident_abi = elfkit::types::Abi::SYSV;
        elf.validate().expect("validation failed");
        elf.elf.header.machine = elfkit::types::Machine::QDSP6;
        elf.validate().expect_err("allowed wrong machine");
        elf.elf.header.machine = elfkit::types::Machine::BPF;
        elf.validate().expect("validation failed");
        elf.elf.header.etype = elfkit::types::ElfType::REL;
        elf.validate().expect_err("allowed wrong type");
        elf.elf.header.etype = elfkit::types::ElfType::DYN;
        elf.validate().expect("validation failed");
    }

    #[test]
    fn test_relocate() {
        let mut file = File::open("tests/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        EBpfElf::load(&elf_bytes).expect("validation failed");
    }
}
