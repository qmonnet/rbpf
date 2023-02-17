#![no_main]

extern crate rbpf;
extern crate libfuzzer_sys;

use std::env;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    prog: Vec<u8>
}

fuzz_target!(|data: FuzzData| {
    env::set_var("RUSTFLAGS", "-C instrument coverage");

    let prog = data.prog;

    let vm = rbpf::EbpfVmNoData::new(Some(&prog));

    if vm.is_err() {
        // The verifier returns Result, possible Err()
        return;
    }

    let res = vm.unwrap().execute_program().unwrap();
});
