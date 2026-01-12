// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2024 Akenes SA <wouter.dullaert@exoscale.ch>

extern crate elf;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::path::PathBuf;
use std::{ptr::addr_of};

extern crate rbpf;

const OBJ_FILE_PATH: &str = "examples/allowed-memory/allowed-memory.o";

const BPF_MAP_LOOKUP_ELEM_IDX: u32 = 1;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Key {
    pub protocol: u8,
}

#[repr(C, packed)]
pub struct Value {
    pub result: i32,
}

static MAP_VALUE: Value = Value { result: 1 };

fn bpf_lookup_elem(_map: u64, key_addr: u64, _flags: u64, _u4: u64, _u5: u64) -> u64 {
    let key: Key = unsafe { *(key_addr as *const Key) };
    if key.protocol == 1 {
        return addr_of!(MAP_VALUE) as u64;
    }
    0
}

fn get_prog_data(filename: &str) -> Vec<u8> {
    let path = PathBuf::from(filename);
    let file_data = std::fs::read(path).expect("Could not read file");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Fail to parse ELF file");

    let classifier_section_header = match file.section_header_by_name("classifier") {
        Ok(Some(header)) => header,
        Ok(None) => panic!("No .classifier section found"),
        Err(e) => panic!("Error while searching for classifier section: {}", e),
    };

    file
        .section_data(&classifier_section_header)
        .expect("Failed to get classifier section data").0.to_vec()
}

fn main() {
    let prog = get_prog_data(OBJ_FILE_PATH);

    let mut vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.register_helper(BPF_MAP_LOOKUP_ELEM_IDX, bpf_lookup_elem)
        .unwrap();

    let start = addr_of!(MAP_VALUE) as u64;
    vm.register_allowed_memory(start..start + size_of::<Value>() as u64);

    let res = vm.execute_program().unwrap();
    assert_eq!(res, 1);
}
