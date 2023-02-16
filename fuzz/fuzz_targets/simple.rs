#![no_main]

extern crate rbpf;

extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    prog: Vec<u8>
}

fuzz_target!(|data: FuzzData| {
    let prog = data.prog;

    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();

    let res = vm.execute_program().unwrap();
});
