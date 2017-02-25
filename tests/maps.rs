// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


extern crate rbpf;

use rbpf::maps::*;
use rbpf::helpers;
use rbpf::assembler;
use std::collections::HashMap;

#[test]
fn test_hashmap() {
    unsafe {
        let mut maps: EbpfMapContainer = Default::default();
        EBPF_MAPS = &mut maps;

        let mut hm = EbpfMapType::HashMap { map : EbpfHashMap { map: HashMap::new() }};
        match hm {
            EbpfMapType::HashMap { map } => map.map.insert(0x1010101032323232, 0x1234).unwrap(),
            _ => 0
        };

        (*EBPF_MAPS).maps.insert(10101, hm);
    };

    let prog_push = assembler::assemble("
        lddw r7, 0x1010101032323232
        stxdw [r10-8], r7

        mov r3, 0
        mov r4, 0
        mov r5, 0

        mov r2, r10
        mov r6, 0x8
        sub r2, r6

        lddw r1, 0x10101

        call 1
        exit
    ").unwrap();

    let mut vm = rbpf::EbpfVmNoData::new(&prog_push);
    vm.register_helper(helpers::BPF_MAP_LOOKUP_ELEM_IDX, helpers::bpf_map_lookup_elem);
    vm.register_helper(helpers::BPF_MAP_UPDATE_ELEM_IDX, helpers::bpf_map_update_elem);
    vm.register_helper(helpers::BPF_MAP_DELETE_ELEM_IDX, helpers::bpf_map_delete_elem);

    let res = vm.prog_exec();
    println!("Program returned: {:?} ({:#x})", res, res);
    assert_eq!(res, 0xffffffff);
}
