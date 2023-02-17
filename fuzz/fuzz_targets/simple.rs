#![no_main]

extern crate rbpf;
extern crate libfuzzer_sys;
use crate::programgenerator::Program;
mod programgenerator;

use std::env;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    prog: Program
}

fuzz_target!(|data: FuzzData| {
    env::set_var("RUSTFLAGS", "-C instrument coverage");

    let prog = data.prog.instructions;

    let vm = rbpf::EbpfVmNoData::new(Some(&prog));

    if vm.is_err() {
        // The verifier returns Result, possible Err()
        return;
    }

    let _res = vm.unwrap().execute_program().unwrap();
});
