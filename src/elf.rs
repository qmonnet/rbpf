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
use std::collections::HashMap;
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::mem;
use std::str;

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
    calls: HashMap<u32, usize>,
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
        let mut ebpf_elf = EBpfElf { elf, calls: HashMap::new() };
        ebpf_elf.validate()?;
        ebpf_elf.relocate()?;
        Ok(ebpf_elf)
    }

    /// Get the .text section bytes
    pub fn get_text_bytes(&self) -> Result<&[u8], Error> {
        EBpfElf::content_to_bytes(self.get_section(".text")?)
    }

    /// Get a vector of read-only data sections
    pub fn get_rodata(&self) -> Result<Vec<&[u8]>, Error> {
        let rodata: Result<Vec<_>, _> = self
            .elf
            .sections
            .iter()
            .filter(|section| section.name == b".rodata")
            .map(EBpfElf::content_to_bytes)
            .collect();
        if let Ok(ref v) = rodata {
            if v.is_empty() {
                Err(Error::new(ErrorKind::Other, "Error: No RO data"))?;
            }
        }
        rodata
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> Result<usize, Error> {
        let entry = self.elf.header.entry;
        let text = self.get_section(".text")?;
        if entry < text.header.addr || entry > text.header.addr + text.header.size {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Entrypoint out of bounds",
            ))?
        }
        let offset = (entry - text.header.addr) as usize;
        if offset % ebpf::INSN_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Error: Entrypoint not multple of instruction size",
            ))?
        }
        Ok(offset / ebpf::INSN_SIZE)
    }

    /// Get a symbol's instruction offset
    pub fn lookup_bpf_call(&self, hash: u32) -> Option<&usize> {
        self.calls.get(&hash)
    }

    /// Report information on a symbol that failed to be resolved
    pub fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), Error> {
        let file_offset =
            insn_offset * ebpf::INSN_SIZE + self.get_section(".text")?.header.addr as usize;

        let symbols = match self.get_section(".dynsym")?.content {
            elfkit::SectionContent::Symbols(ref bytes) => bytes,
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .dynsym contents",
            ))?,
        };

        let raw_relocation_bytes = match self.get_section(".rel.dyn")?.content {
            elfkit::SectionContent::Raw(ref bytes) => bytes,
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get .rel.dyn contents",
            ))?,
        };
        let relocations = EBpfElf::get_relocations(&raw_relocation_bytes[..])?;

        let mut name = "Unknown";
        for relocation in relocations.iter() {
            match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                Some(BPFRelocationType::R_BPF_64_32) => {
                    if relocation.addr as usize == file_offset {
                        name = match str::from_utf8(&symbols[relocation.sym as usize].name) {
                            Ok(string) => string,
                            Err(_) => "Malformed symbol name",
                        };
                    }
                }
                _ => (),
            }
        }
        Err(Error::new(
            ErrorKind::Other,
            format!(
                "Error: Unresolved symbol ({}) at instruction #{:?} (ELF file offset {:#x})",
                name,
                file_offset,
                file_offset / ebpf::INSN_SIZE
            ),
        ))?
    }

    fn get_section(&self, name: &str) -> Result<(&elfkit::Section), Error> {
        match self
            .elf
            .sections
            .iter()
            .find(|section| section.name == name.as_bytes())
        {
            Some(section) => Ok(section),
            None => Err(Error::new(
                ErrorKind::Other,
                format!("Error: No {} section found", name),
            ))?,
        }
    }

    /// Converts a section's raw contents to a slice
    fn content_to_bytes(section: &elfkit::section::Section) -> Result<&[u8], Error> {
        match section.content {
            elfkit::SectionContent::Raw(ref bytes) => Ok(bytes),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to get section contents",
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
        let mut calls: HashMap<u32, usize> = HashMap::new();
        let text_bytes = {
            let raw_relocation_bytes = match self.get_section(".rel.dyn") {
                Ok(section) => match section.content {
                    elfkit::SectionContent::Raw(ref bytes) => bytes,
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Failed to get .rel.dyn contents",
                    ))?,
                },
                Err(_) => return Ok(()), // no relocation section, no need to relocate
            };
            let relocations = EBpfElf::get_relocations(&raw_relocation_bytes[..])?;

            let text_section = self.get_section(".text")?;
            let mut text_bytes = match text_section.content {
                elfkit::SectionContent::Raw(ref bytes) => bytes.clone(),
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .text contents",
                ))?,
            };
            let text_va = text_section.header.addr;

            let rodata_section = self
                .elf
                .sections
                .iter()
                .find(|section| section.name == b".rodata");
            
            let symbols = match self.get_section(".dynsym")?.content {
                elfkit::SectionContent::Symbols(ref symbols) => symbols,
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .dynsym contents",
                ))?,
            };

            for relocation in relocations.iter() {
                match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                    Some(BPFRelocationType::R_BPF_64_RELATIVE) => {
                        // The .text section has a reference to a symbol in the .rodata section

                        let rodata_section = match rodata_section {
                            Some(section) => section,
                            None => Err(Error::new(
                                ErrorKind::Other,
                                "Error: No .rodata section found",
                            ))?,
                        };

                        // Offset of the instruction in the text section being relocated
                        let mut imm_offset =
                            (relocation.addr - text_va) as usize + BYTE_OFFSET_IMMEDIATE;
                        // Read the instruction's immediate field which contains the rodata
                        // symbol's virtual address
                        let ro_va = LittleEndian::read_u32(
                            &text_bytes[imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                        ) as u64;
                        // Convert into an offset into the rodata section by subtracting
                        // the rodata section's base virtual address
                        let ro_offset = ro_va - rodata_section.header.addr;
                        // Get the rodata's physical address
                        let rodata_pa = match rodata_section.content {
                            elfkit::SectionContent::Raw(ref raw) => raw,
                            _ => Err(Error::new(
                                ErrorKind::Other,
                                "Error: Failed to get .rodata contents",
                            ))?,
                        }
                        .as_ptr() as u64;
                        // Calculator the symbol's physical address within the rodata section
                        let symbol_addr = rodata_pa + ro_offset;

                        // Instruction lddw spans two instruction slots, split the
                        // symbol's address into two and write into both slot's imm field
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
                        // instruction's imm field.  Later that hash will be
                        // used to look up the function location.

                        let symbol = &symbols[relocation.sym as usize];
                        let hash = ebpf::hash_symbol_name(&symbol.name);
                        let imm_offset =
                            (relocation.addr - text_va) as usize + BYTE_OFFSET_IMMEDIATE;
                        LittleEndian::write_u32(
                            &mut text_bytes[imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE], hash);
                        if symbol.stype == elfkit::types::SymbolType::FUNC && symbol.value != 0 { 
                            calls.insert(hash, (symbol.value - text_va) as usize / ebpf::INSN_SIZE);
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Unhandled relocation type",
                    ))?,
                }
            }
            text_bytes
        };

        mem::swap(&mut self.calls, &mut calls);

        // Write back fixed-up text section
        let mut text_section = match self
            .elf
            .sections
            .iter_mut()
            .find(|section| section.name == b".text")
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
    /// Elfkit does not form BPF relocations and instead just provides raw bytes
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
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
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
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        EBpfElf::load(&elf_bytes).expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        assert_eq!(0, elf.get_entrypoint_instruction_offset().expect("failed to get entrypoint"));
        elf.elf.header.entry = elf.elf.header.entry + 8;
        assert_eq!(1, elf.get_entrypoint_instruction_offset().expect("failed to get entrypoint"));
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint out of bounds")]
    fn test_entrypoint_before_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint out of bounds")]
    fn test_entrypoint_after_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "Error: Entrypoint not multple of instruction size")]
    fn test_entrypoint_not_multiple_of_instruction_size() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = elf.elf.header.entry + ebpf::INSN_SIZE as u64 + 1 ;
        elf.get_entrypoint_instruction_offset().unwrap();
    }
}


