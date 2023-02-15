#![no_main]

use libfuzzer_sys::fuzz_target;

extern crate rbpf;

fuzz_target!(|data: &[u8]| {
    println!("Hello World!");
});
