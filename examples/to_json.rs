// Copyright 2017 Quentin Monnet <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


#[macro_use]
extern crate json;

extern crate rbpf;
use rbpf::disassembler;

// Turn a program into a JSON string.
//
// Relies on `json` crate.
//
// You may copy this function and adapt it according to your needs. For instance, you may want to:
//
// * Remove the "desc" (description) attributes from the output.
// * Print integers as integers, and not as strings containing their hexadecimal representation
//   (just replace the relevant `format!()` calls by the commented values.
fn to_json(prog: &std::vec::Vec<u8>) -> String {

    // This call returns a high-level representation of the instructions, with the two parts of
    // `LD_DW_IMM` instructions merged, and name and descriptions of the instructions.
    // If you prefer to use a lower-level representation, use `ebpf::to_insn_vec()` function
    // instead.
    let insns = disassembler::to_insn_vec(&prog);
    let mut json_insns = vec![];
    for insn in insns {
        json_insns.push(object!(
                "opc"  => format!("{:#x}", insn.opc), // => insn.opc,
                "dst"  => format!("{:#x}", insn.dst), // => insn.dst,
                "src"  => format!("{:#x}", insn.src), // => insn.src,
                "off"  => format!("{:#x}", insn.off), // => insn.off,
                // Warning: for imm we use a i64 instead of a i32 (to have correct values for
                // `lddw` operation. If we print a number in the JSON this is not a problem, the
                // internal i64 has the same value with extended sign on 32 most significant bytes.
                // If we print the hexadecimal value as a string however, we want to cast as a i32
                // to prevent all other instructions to print spurious `ffffffff` prefix if the
                // number is negative. When values takes more than 32 bits with `lddw`, the cast
                // has no effect and the complete value is printed anyway.
                "imm"  => format!("{:#x}", insn.imm as i32), // => insn.imm,
                "desc" => format!("{}",    insn.desc)
            )
        );
    }
    json::stringify_pretty(object!(
        "size"  => json_insns.len(),
        "insns" => json_insns
        ), 4)
}

// Print a JSON string representing the program to standard output.
fn main() {
    let prog = vec![
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x2d, 0x23, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x69, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x71, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x02, 0x0e, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x79, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x15, 0x02, 0x08, 0x00, 0x99, 0x99, 0x00, 0x00,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    println!("{}", to_json(&prog));
}
