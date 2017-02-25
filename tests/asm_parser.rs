// Copyright 2017 Rich Lane <lanerl@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


extern crate rbpf;
extern crate combine;

use rbpf::asm_parser::{Instruction, Operand, parse};

#[test]
fn test_empty() {
    assert_eq!(parse(""), Ok(vec![]));
}

#[test]
fn test_exit() {
    // No operands.
    assert_eq!(parse("exit"),
               Ok(vec![Instruction {
                           name: "exit".to_string(),
                           operands: vec![],
                       }]));
}

#[test]
fn test_lsh() {
    // Register and immediate operands.
    assert_eq!(parse("lsh r3, 0x20"),
               Ok(vec![Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(0x20)],
                       }]));
}

#[test]
fn test_ja() {
    // Jump offset operand.
    assert_eq!(parse("ja +1"),
               Ok(vec![Instruction {
                           name: "ja".to_string(),
                           operands: vec![Operand::Integer(1)],
                       }]));
}

#[test]
fn test_ldxh() {
    // Register and memory operands.
    assert_eq!(parse("ldxh r4, [r1+12]"),
               Ok(vec![Instruction {
                           name: "ldxh".to_string(),
                           operands: vec![Operand::Register(4), Operand::Memory(1, 12)],
                       }]));
}

#[test]
fn test_tcp_sack() {
    // Sample program from ubpf.
    let src = "\
ldxb r2, [r1+12]
ldxb r3, [r1+13]
lsh r3, 0x8
or r3, r2
mov r0, 0x0
jne r3, 0x8, +37
ldxb r2, [r1+23]
jne r2, 0x6, +35
ldxb r2, [r1+14]
add r1, 0xe
and r2, 0xf
lsh r2, 0x2
add r1, r2
mov r0, 0x0
ldxh r4, [r1+12]
add r1, 0x14
rsh r4, 0x2
and r4, 0x3c
mov r2, r4
add r2, 0xffffffec
mov r5, 0x15
mov r3, 0x0
jgt r5, r4, +20
mov r5, r3
lsh r5, 0x20
arsh r5, 0x20
mov r4, r1
add r4, r5
ldxb r5, [r4]
jeq r5, 0x1, +4
jeq r5, 0x0, +12
mov r6, r3
jeq r5, 0x5, +9
ja +2
add r3, 0x1
mov r6, r3
ldxb r3, [r4+1]
add r3, r6
lsh r3, 0x20
arsh r3, 0x20
jsgt r2, r3, -18
ja +1
mov r0, 0x1
exit
";

    assert_eq!(parse(src),
               Ok(vec![Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(2), Operand::Memory(1, 12)],
                       },
                       Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(3), Operand::Memory(1, 13)],
                       },
                       Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(8)],
                       },
                       Instruction {
                           name: "or".to_string(),
                           operands: vec![Operand::Register(3), Operand::Register(2)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(0), Operand::Integer(0)],
                       },
                       Instruction {
                           name: "jne".to_string(),
                           operands: vec![Operand::Register(3),
                                          Operand::Integer(8),
                                          Operand::Integer(37)],
                       },
                       Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(2), Operand::Memory(1, 23)],
                       },
                       Instruction {
                           name: "jne".to_string(),
                           operands: vec![Operand::Register(2),
                                          Operand::Integer(6),
                                          Operand::Integer(35)],
                       },
                       Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(2), Operand::Memory(1, 14)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(1), Operand::Integer(14)],
                       },
                       Instruction {
                           name: "and".to_string(),
                           operands: vec![Operand::Register(2), Operand::Integer(15)],
                       },
                       Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(2), Operand::Integer(2)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(1), Operand::Register(2)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(0), Operand::Integer(0)],
                       },
                       Instruction {
                           name: "ldxh".to_string(),
                           operands: vec![Operand::Register(4), Operand::Memory(1, 12)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(1), Operand::Integer(20)],
                       },
                       Instruction {
                           name: "rsh".to_string(),
                           operands: vec![Operand::Register(4), Operand::Integer(2)],
                       },
                       Instruction {
                           name: "and".to_string(),
                           operands: vec![Operand::Register(4), Operand::Integer(60)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(2), Operand::Register(4)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(2), Operand::Integer(4294967276)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(5), Operand::Integer(21)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(0)],
                       },
                       Instruction {
                           name: "jgt".to_string(),
                           operands: vec![Operand::Register(5),
                                          Operand::Register(4),
                                          Operand::Integer(20)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(5), Operand::Register(3)],
                       },
                       Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(5), Operand::Integer(32)],
                       },
                       Instruction {
                           name: "arsh".to_string(),
                           operands: vec![Operand::Register(5), Operand::Integer(32)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(4), Operand::Register(1)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(4), Operand::Register(5)],
                       },
                       Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(5), Operand::Memory(4, 0)],
                       },
                       Instruction {
                           name: "jeq".to_string(),
                           operands: vec![Operand::Register(5),
                                          Operand::Integer(1),
                                          Operand::Integer(4)],
                       },
                       Instruction {
                           name: "jeq".to_string(),
                           operands: vec![Operand::Register(5),
                                          Operand::Integer(0),
                                          Operand::Integer(12)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(6), Operand::Register(3)],
                       },
                       Instruction {
                           name: "jeq".to_string(),
                           operands: vec![Operand::Register(5),
                                          Operand::Integer(5),
                                          Operand::Integer(9)],
                       },
                       Instruction {
                           name: "ja".to_string(),
                           operands: vec![Operand::Integer(2)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(1)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(6), Operand::Register(3)],
                       },
                       Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(3), Operand::Memory(4, 1)],
                       },
                       Instruction {
                           name: "add".to_string(),
                           operands: vec![Operand::Register(3), Operand::Register(6)],
                       },
                       Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(32)],
                       },
                       Instruction {
                           name: "arsh".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(32)],
                       },
                       Instruction {
                           name: "jsgt".to_string(),
                           operands: vec![Operand::Register(2),
                                          Operand::Register(3),
                                          Operand::Integer(-18)],
                       },
                       Instruction {
                           name: "ja".to_string(),
                           operands: vec![Operand::Integer(1)],
                       },
                       Instruction {
                           name: "mov".to_string(),
                           operands: vec![Operand::Register(0), Operand::Integer(1)],
                       },
                       Instruction {
                           name: "exit".to_string(),
                           operands: vec![],
                       }]));
}

#[test]
fn test_error_eof() {
    // Unexpected end of input in a register name.
    assert_eq!(parse("lsh r"),
               Err("Parse error at line 1 column 6: unexpected end of input, expected digit"
                   .to_string()));
}

#[test]
fn test_error_unexpected_character() {
    // Unexpected character at end of input.
    assert_eq!(parse("exit\n^"),
               Err("Parse error at line 2 column 1: unexpected '^', expected end of input"
                   .to_string()));
}

#[test]
fn test_initial_whitespace() {
    assert_eq!(parse(" 
                      exit"),
               Ok(vec![Instruction {
                           name: "exit".to_string(),
                           operands: vec![],
                       }]));
}
