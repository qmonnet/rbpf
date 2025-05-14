// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2024 Akenes SA <wouter.dullaert@exoscale.ch>

extern crate elf;
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

fn main() {
    let file = elf::File::open_path(OBJ_FILE_PATH).unwrap();
    let func = file.get_section("classifier").unwrap();

    let mut vm = rbpf::EbpfVmNoData::new(Some(&func.data)).unwrap();
    vm.register_helper(BPF_MAP_LOOKUP_ELEM_IDX, bpf_lookup_elem)
        .unwrap();

    let start = addr_of!(MAP_VALUE) as u64;
    vm.register_allowed_memory(start..start + size_of::<Value>() as u64);

    let res = vm.execute_program().unwrap();
    assert_eq!(res, 1);
}
