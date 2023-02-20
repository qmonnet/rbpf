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

    let interpreter_result = match rbpf::EbpfVmNoData::new(Some(&prog)) {
        Ok(ref vm) => { match vm.execute_program() {
            Ok(result) => result,
            Err(error) => return,
        }},
        Err(error) => return,
    };
    // Note: Kan se at "fejl" er at vi ikke håndtere "unknown helper function" - så det er ikke rigtige fejl
    // + not implemented fejl
});
