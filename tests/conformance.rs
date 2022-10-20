// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2022 Isovalent, Inc. <quentin@isovalent.com>

#[macro_use]
extern crate lazy_static;
extern crate rbpf;
extern crate regex;

use rbpf::assembler::assemble;
use regex::Regex;
use std::fs::File;
use std::io::{prelude::*, BufReader, Error, ErrorKind};
use std::path::PathBuf;

macro_rules! generate_tests {
    ($($test_name:ident: $file_path:expr,)*) => {
    $(
        #[test]
        fn $test_name() {
            let mut test_file = PathBuf::new();
            test_file.push("../");
            test_file.push("bpf_conformance");
            test_file.push("tests");
            test_file.push($file_path);
            run_test(&test_file);
        }
    )*
    }
}

enum Context {
    Asm,
    Result,
    Mem,
    Raw,
    Error,
    Other,
}

fn update_context(directive: &str) -> Context {
    match directive {
        "asm" => Context::Asm,
        "result" => Context::Result,
        "mem" => Context::Mem,
        "raw" => Context::Raw,
        "error" => Context::Error,
        _ => Context::Other,
    }
}

fn read_test(filename: &str) -> (Result<Vec<u8>, String>, u64) {
    lazy_static! {
        static ref RE_DISCARD: Regex = Regex::new(r"(^#|^\s*$)").unwrap();
        static ref RE_DIRECTIVE: Regex = Regex::new(r"^-- (?P<directive>.*)").unwrap();
    }

    let test_file = File::open(filename).expect("test file should be accessible");
    let reader = BufReader::new(test_file);

    let mut result: u64 = 0;
    let mut instructions: String = "".to_owned();

    let mut current_context = Context::Other;

    for line in reader.lines() {
        if RE_DISCARD.is_match(&line.as_ref().unwrap()) {
            continue;
        }

        match RE_DIRECTIVE.captures(&line.as_ref().unwrap()) {
            Some(x) => current_context = update_context(x.name("directive").unwrap().into()),
            None => match current_context {
                Context::Asm => {
                    instructions.push_str(&line.unwrap());
                    instructions.push_str("\n");
                },
                Context::Result => {
                    result =
                        u64::from_str_radix(line.unwrap().to_string().trim_start_matches("0x"), 16)
                            .unwrap()
                }
                Context::Other => (),
                _ => unimplemented!(),
            },
        }
    }

    //println!("{:?} -> {:?}", instructions, result);
    return (assemble(&instructions), result);
}

fn run_prog(program: &[u8], expected_result: u64) -> Result<(), Error> {
    //println!("{:?} -> {:?}", program, expected_result);
    let vm = rbpf::EbpfVmNoData::new(Some(program)).unwrap();
    match vm.execute_program() {
        Ok(x) if x == expected_result => Ok(()),
        Ok(x) => Err(Error::new(
            ErrorKind::Other,
            format!(
                "wrong result: got {:#x}, expected {:#x})",
                x, expected_result
            ),
        )),
        Err(msg) => Err(Error::new(
            ErrorKind::Other,
            format!("program run failed: {:?}", msg),
        )),
    }
}

fn run_test(filepath: &PathBuf) {
        let (program, result) = read_test(filepath.to_str().unwrap());
        run_prog(&program.unwrap(), result).unwrap();

        //let (program, result) = match read_test(filepath.to_str().unwrap()) {
        //    (Err(msg), _) => {
        //        println!("ASMF {:?}: {:?}", filepath, msg);
        //        return
        //    }
        //    (Ok(x), result) => (x, result),
        //};
        //match run_prog(&program, result) {
        //    Ok(_) => println!("PASS {:?}", filepath),
        //    Err(msg) => println!("FAIL {:?}: {:?}", filepath, msg),
        //}

}

//fn conformance_tests() {
//    for test_file in fs::read_dir("/home/qmo/dev/bpf_conformance/tests").unwrap() {
//        let filepath = test_file.as_ref().unwrap().path();
//        if !filepath.is_file() {
//            continue;
//        }
//        run_test(&filepath)
//    }
//}

generate_tests! {
    conformance_add: "add.data",
    conformance_add64: "add64.data",
    conformance_alu_arith: "alu-arith.data",
    conformance_alu_bit: "alu-bit.data",
    conformance_alu64_arith: "alu64-arith.data",
    conformance_alu64_bit: "alu64-bit.data",
    conformance_arsh_reg: "arsh-reg.data",
    conformance_arsh: "arsh.data",
    conformance_arsh32_high_shift: "arsh32-high-shift.data",
    conformance_arsh64: "arsh64.data",
    conformance_be16_high: "be16-high.data",
    conformance_be16: "be16.data",
    conformance_be32_high: "be32-high.data",
    conformance_be32: "be32.data",
    conformance_be64: "be64.data",
    conformance_call_unwind_fail: "call_unwind_fail.data",
    conformance_div_by_zero_reg: "div-by-zero-reg.data",
    conformance_div32_high_divisor: "div32-high-divisor.data",
    conformance_div32_imm: "div32-imm.data",
    conformance_div32_reg: "div32-reg.data",
    conformance_div64_by_zero_reg: "div64-by-zero-reg.data",
    conformance_div64_imm: "div64-imm.data",
    conformance_div64_negative_imm: "div64-negative-imm.data",
    conformance_div64_negative_reg: "div64-negative-reg.data",
    conformance_div64_reg: "div64-reg.data",
    conformance_exit_not_last: "exit-not-last.data",
    conformance_exit: "exit.data",
    conformance_jeq_imm: "jeq-imm.data",
    conformance_jeq_reg: "jeq-reg.data",
    conformance_jeq32_imm: "jeq32-imm.data",
    conformance_jeq32_reg: "jeq32-reg.data",
    conformance_jge_imm: "jge-imm.data",
    conformance_jge32_imm: "jge32-imm.data",
    conformance_jge32_reg: "jge32-reg.data",
    conformance_jgt_imm: "jgt-imm.data",
    conformance_jgt_reg: "jgt-reg.data",
    conformance_jgt32_imm: "jgt32-imm.data",
    conformance_jgt32_reg: "jgt32-reg.data",
    conformance_jit_bounce: "jit-bounce.data",
    conformance_jle_imm: "jle-imm.data",
    conformance_jle_reg: "jle-reg.data",
    conformance_jle32_imm: "jle32-imm.data",
    conformance_jle32_reg: "jle32-reg.data",
    conformance_jlt_imm: "jlt-imm.data",
    conformance_jlt_reg: "jlt-reg.data",
    conformance_jlt32_imm: "jlt32-imm.data",
    conformance_jlt32_reg: "jlt32-reg.data",
    conformance_jne_reg: "jne-reg.data",
    conformance_jne32_imm: "jne32-imm.data",
    conformance_jne32_reg: "jne32-reg.data",
    conformance_jset_imm: "jset-imm.data",
    conformance_jset_reg: "jset-reg.data",
    conformance_jset32_imm: "jset32-imm.data",
    conformance_jset32_reg: "jset32-reg.data",
    conformance_jsge_imm: "jsge-imm.data",
    conformance_jsge_reg: "jsge-reg.data",
    conformance_jsge32_imm: "jsge32-imm.data",
    conformance_jsge32_reg: "jsge32-reg.data",
    conformance_jsgt_imm: "jsgt-imm.data",
    conformance_jsgt_reg: "jsgt-reg.data",
    conformance_jsgt32_imm: "jsgt32-imm.data",
    conformance_jsgt32_reg: "jsgt32-reg.data",
    conformance_jsle_imm: "jsle-imm.data",
    conformance_jsle_reg: "jsle-reg.data",
    conformance_jsle32_imm: "jsle32-imm.data",
    conformance_jsle32_reg: "jsle32-reg.data",
    conformance_jslt_imm: "jslt-imm.data",
    conformance_jslt_reg: "jslt-reg.data",
    conformance_jslt32_imm: "jslt32-imm.data",
    conformance_jslt32_reg: "jslt32-reg.data",
    conformance_lddw: "lddw.data",
    conformance_lddw2: "lddw2.data",
    conformance_ldxb_all: "ldxb-all.data",
    conformance_ldxb: "ldxb.data",
    conformance_ldxdw: "ldxdw.data",
    conformance_ldxh_all: "ldxh-all.data",
    conformance_ldxh_all2: "ldxh-all2.data",
    conformance_ldxh_same_reg: "ldxh-same-reg.data",
    conformance_ldxh: "ldxh.data",
    conformance_ldxw_all: "ldxw-all.data",
    conformance_ldxw: "ldxw.data",
    conformance_le16: "le16.data",
    conformance_le32: "le32.data",
    conformance_le64: "le64.data",
    conformance_lock_add: "lock_add.data",
    conformance_lock_add32: "lock_add32.data",
    conformance_lock_and: "lock_and.data",
    conformance_lock_and32: "lock_and32.data",
    conformance_lock_cmpxchg: "lock_cmpxchg.data",
    conformance_lock_cmpxchg32: "lock_cmpxchg32.data",
    conformance_lock_or: "lock_or.data",
    conformance_lock_or32: "lock_or32.data",
    conformance_lock_xchg: "lock_xchg.data",
    conformance_lock_xchg32: "lock_xchg32.data",
    conformance_lock_xor: "lock_xor.data",
    conformance_lock_xor32: "lock_xor32.data",
    conformance_lsh_reg: "lsh-reg.data",
    conformance_mem_len: "mem-len.data",
    conformance_mod_by_zero_reg: "mod-by-zero-reg.data",
    conformance_mod: "mod.data",
    conformance_mod32: "mod32.data",
    conformance_mod64_by_zero_reg: "mod64-by-zero-reg.data",
    conformance_mod64: "mod64.data",
    conformance_mov: "mov.data",
    conformance_mov64_sign_extend: "mov64-sign-extend.data",
    conformance_mul32_imm: "mul32-imm.data",
    conformance_mul32_reg_overflow: "mul32-reg-overflow.data",
    conformance_mul32_reg: "mul32-reg.data",
    conformance_mul64_imm: "mul64-imm.data",
    conformance_mul64_reg: "mul64-reg.data",
    conformance_neg: "neg.data",
    conformance_neg64: "neg64.data",
    conformance_prime: "prime.data",
    conformance_rsh_reg: "rsh-reg.data",
    conformance_rsh32: "rsh32.data",
    conformance_stack: "stack.data",
    conformance_stb: "stb.data",
    conformance_stdw: "stdw.data",
    conformance_sth: "sth.data",
    conformance_stw: "stw.data",
    conformance_stxb_all: "stxb-all.data",
    conformance_stxb_all2: "stxb-all2.data",
    conformance_stxb_chain: "stxb-chain.data",
    conformance_stxb: "stxb.data",
    conformance_stxdw: "stxdw.data",
    conformance_stxh: "stxh.data",
    conformance_stxw: "stxw.data",
    conformance_subnet: "subnet.data",
}
