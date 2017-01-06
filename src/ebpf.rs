// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


use std;

pub const PROG_MAX_INSNS: usize = 4096;
pub const INSN_SIZE: usize = 8;
pub const PROG_MAX_SIZE: usize = PROG_MAX_INSNS * INSN_SIZE;
pub const STACK_SIZE: usize = 512;

// eBPF op codes.
// See also https://www.kernel.org/doc/Documentation/networking/filter.txt

// Three least significant bits are operation class:
pub const BPF_LD    : u8 = 0x00;
pub const BPF_LDX   : u8 = 0x01;
pub const BPF_ST    : u8 = 0x02;
pub const BPF_STX   : u8 = 0x03;
pub const BPF_ALU   : u8 = 0x04;
pub const BPF_JMP   : u8 = 0x05;
// [ class 6 unused, reserved for future use ]
pub const BPF_ALU64 : u8 = 0x07;

// For load and store instructions:
// +------------+--------+------------+
// |   3 bits   | 2 bits |   3 bits   |
// |    mode    |  size  | insn class |
// +------------+--------+------------+
// (MSB)                          (LSB)

// Size modifiers:
pub const BPF_W     : u8 = 0x00; // word
pub const BPF_H     : u8 = 0x08; // half-word
pub const BPF_B     : u8 = 0x10; // byte
pub const BPF_DW    : u8 = 0x18; // double word

// Mode modifiers:
pub const BPF_IMM   : u8 = 0x00;
pub const BPF_ABS   : u8 = 0x20;
pub const BPF_IND   : u8 = 0x40;
pub const BPF_MEM   : u8 = 0x60;
// [ 0x80 reserved ]
// [ 0xa0 reserved ]
pub const BPF_XADD  : u8 = 0xc0; // exclusive add

// For arithmetic (BPF_ALU/BPF_ALU64) and jump (BPF_JMP) instructions:
// +----------------+--------+--------+
// |     4 bits     |1 b.|   3 bits   |
// | operation code | src| insn class |
// +----------------+----+------------+
// (MSB)                          (LSB)

// Source modifiers:
pub const BPF_K     : u8 = 0x00; // use 32-bit immediate as source operand
pub const BPF_X     : u8 = 0x08; // use `src` register as source operand

// Operation codes -- BPF_ALU or BPF_ALU64 classes:
pub const BPF_ADD   : u8 = 0x00;
pub const BPF_SUB   : u8 = 0x10;
pub const BPF_MUL   : u8 = 0x20;
pub const BPF_DIV   : u8 = 0x30;
pub const BPF_OR    : u8 = 0x40;
pub const BPF_AND   : u8 = 0x50;
pub const BPF_LSH   : u8 = 0x60;
pub const BPF_RSH   : u8 = 0x70;
pub const BPF_NEG   : u8 = 0x80;
pub const BPF_MOD   : u8 = 0x90;
pub const BPF_XOR   : u8 = 0xa0;
pub const BPF_MOV   : u8 = 0xb0; // mov reg to reg
pub const BPF_ARSH  : u8 = 0xc0; // sign extending shift right
pub const BPF_END   : u8 = 0xd0; // endianness conversion

// Operation codes -- BPF_JMP class:
pub const BPF_JA    : u8 = 0x00;
pub const BPF_JEQ   : u8 = 0x10;
pub const BPF_JGT   : u8 = 0x20;
pub const BPF_JGE   : u8 = 0x30;
pub const BPF_JSET  : u8 = 0x40;
pub const BPF_JNE   : u8 = 0x50; // jump !=
pub const BPF_JSGT  : u8 = 0x60; // signed '>'
pub const BPF_JSGE  : u8 = 0x70; // signed '>='
pub const BPF_CALL  : u8 = 0x80; // function call
pub const BPF_EXIT  : u8 = 0x90; // function return

// Op codes
// (Following operation names are not “official”, but may be proper to rbpf; Linux kernel only
// combines above flags and does not attribute a name per operation.)

pub const LD_ABS_B   : u8 = BPF_LD    | BPF_ABS | BPF_B;
pub const LD_ABS_H   : u8 = BPF_LD    | BPF_ABS | BPF_H;
pub const LD_ABS_W   : u8 = BPF_LD    | BPF_ABS | BPF_W;
pub const LD_ABS_DW  : u8 = BPF_LD    | BPF_ABS | BPF_DW;
pub const LD_IND_B   : u8 = BPF_LD    | BPF_IND | BPF_B;
pub const LD_IND_H   : u8 = BPF_LD    | BPF_IND | BPF_H;
pub const LD_IND_W   : u8 = BPF_LD    | BPF_IND | BPF_W;
pub const LD_IND_DW  : u8 = BPF_LD    | BPF_IND | BPF_DW;

pub const LD_DW_IMM  : u8 = BPF_LD    | BPF_IMM | BPF_DW;
pub const LD_B_REG   : u8 = BPF_LDX   | BPF_MEM | BPF_B;
pub const LD_H_REG   : u8 = BPF_LDX   | BPF_MEM | BPF_H;
pub const LD_W_REG   : u8 = BPF_LDX   | BPF_MEM | BPF_W;
pub const LD_DW_REG  : u8 = BPF_LDX   | BPF_MEM | BPF_DW;
pub const ST_B_IMM   : u8 = BPF_ST    | BPF_MEM | BPF_B;
pub const ST_H_IMM   : u8 = BPF_ST    | BPF_MEM | BPF_H;
pub const ST_W_IMM   : u8 = BPF_ST    | BPF_MEM | BPF_W;
pub const ST_DW_IMM  : u8 = BPF_ST    | BPF_MEM | BPF_DW;
pub const ST_B_REG   : u8 = BPF_STX   | BPF_MEM | BPF_B;
pub const ST_H_REG   : u8 = BPF_STX   | BPF_MEM | BPF_H;
pub const ST_W_REG   : u8 = BPF_STX   | BPF_MEM | BPF_W;
pub const ST_DW_REG  : u8 = BPF_STX   | BPF_MEM | BPF_DW;

pub const ST_W_XADD  : u8 = BPF_STX   | BPF_XADD | BPF_W;
pub const ST_DW_XADD : u8 = BPF_STX   | BPF_XADD | BPF_DW;

pub const ADD32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_ADD;
pub const ADD32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_ADD;
pub const SUB32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_SUB;
pub const SUB32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_SUB;
pub const MUL32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_MUL;
pub const MUL32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_MUL;
pub const DIV32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_DIV;
pub const DIV32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_DIV;
pub const OR32_IMM   : u8 = BPF_ALU   | BPF_K   | BPF_OR;
pub const OR32_REG   : u8 = BPF_ALU   | BPF_X   | BPF_OR;
pub const AND32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_AND;
pub const AND32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_AND;
pub const LSH32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_LSH;
pub const LSH32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_LSH;
pub const RSH32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_RSH;
pub const RSH32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_RSH;
pub const NEG32      : u8 = BPF_ALU   | BPF_NEG;
pub const MOD32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_MOD;
pub const MOD32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_MOD;
pub const XOR32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_XOR;
pub const XOR32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_XOR;
pub const MOV32_IMM  : u8 = BPF_ALU   | BPF_K   | BPF_MOV;
pub const MOV32_REG  : u8 = BPF_ALU   | BPF_X   | BPF_MOV;
pub const ARSH32_IMM : u8 = BPF_ALU   | BPF_K   | BPF_ARSH;
pub const ARSH32_REG : u8 = BPF_ALU   | BPF_X   | BPF_ARSH;

pub const LE         : u8 = BPF_ALU   | BPF_K   | BPF_END;
pub const BE         : u8 = BPF_ALU   | BPF_X   | BPF_END;

pub const ADD64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_ADD;
pub const ADD64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_ADD;
pub const SUB64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_SUB;
pub const SUB64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_SUB;
pub const MUL64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_MUL;
pub const MUL64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_MUL;
pub const DIV64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_DIV;
pub const DIV64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_DIV;
pub const OR64_IMM   : u8 = BPF_ALU64 | BPF_K   | BPF_OR;
pub const OR64_REG   : u8 = BPF_ALU64 | BPF_X   | BPF_OR;
pub const AND64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_AND;
pub const AND64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_AND;
pub const LSH64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_LSH;
pub const LSH64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_LSH;
pub const RSH64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_RSH;
pub const RSH64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_RSH;
pub const NEG64      : u8 = BPF_ALU64 | BPF_NEG;
pub const MOD64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_MOD;
pub const MOD64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_MOD;
pub const XOR64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_XOR;
pub const XOR64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_XOR;
pub const MOV64_IMM  : u8 = BPF_ALU64 | BPF_K   | BPF_MOV;
pub const MOV64_REG  : u8 = BPF_ALU64 | BPF_X   | BPF_MOV;
pub const ARSH64_IMM : u8 = BPF_ALU64 | BPF_K   | BPF_ARSH;
pub const ARSH64_REG : u8 = BPF_ALU64 | BPF_X   | BPF_ARSH;

pub const JA         : u8 = BPF_JMP   | BPF_JA;
pub const JEQ_IMM    : u8 = BPF_JMP   | BPF_K   | BPF_JEQ;
pub const JEQ_REG    : u8 = BPF_JMP   | BPF_X   | BPF_JEQ;
pub const JGT_IMM    : u8 = BPF_JMP   | BPF_K   | BPF_JGT;
pub const JGT_REG    : u8 = BPF_JMP   | BPF_X   | BPF_JGT;
pub const JGE_IMM    : u8 = BPF_JMP   | BPF_K   | BPF_JGE;
pub const JGE_REG    : u8 = BPF_JMP   | BPF_X   | BPF_JGE;
pub const JSET_IMM   : u8 = BPF_JMP   | BPF_K   | BPF_JSET;
pub const JSET_REG   : u8 = BPF_JMP   | BPF_X   | BPF_JSET;
pub const JNE_IMM    : u8 = BPF_JMP   | BPF_K   | BPF_JNE;
pub const JNE_REG    : u8 = BPF_JMP   | BPF_X   | BPF_JNE;
pub const JSGT_IMM   : u8 = BPF_JMP   | BPF_K   | BPF_JSGT;
pub const JSGT_REG   : u8 = BPF_JMP   | BPF_X   | BPF_JSGT;
pub const JSGE_IMM   : u8 = BPF_JMP   | BPF_K   | BPF_JSGE;
pub const JSGE_REG   : u8 = BPF_JMP   | BPF_X   | BPF_JSGE;

pub const CALL       : u8 = BPF_JMP   | BPF_CALL;
pub const TAIL_CALL  : u8 = BPF_JMP   | BPF_X | BPF_CALL;
pub const EXIT       : u8 = BPF_JMP   | BPF_EXIT;

// Used in JIT
pub const BPF_CLS_MASK    : u8 = 0x07;
pub const BPF_ALU_OP_MASK : u8 = 0xf0;

#[derive(Debug)]
pub struct Insn {
    pub opc: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

// Get the nth instruction of an eBPF program
// idx is the index (number) of the instruction.
pub fn get_insn(prog: &std::vec::Vec<u8>, idx: usize) -> Insn {
    // TODO panic if size problem? Should be checked by verifier, though
    let insn = Insn {
        opc:  prog[INSN_SIZE * idx],
        dst:  prog[INSN_SIZE * idx + 1] & 0x0f,
        src: (prog[INSN_SIZE * idx + 1] & 0xf0) >> 4,
        off: unsafe { let x = prog.as_ptr().offset((INSN_SIZE * idx + 2) as isize) as *const i16; *x },
        imm: unsafe { let x = prog.as_ptr().offset((INSN_SIZE * idx + 4) as isize) as *const i32; *x },
    };
    insn
}
