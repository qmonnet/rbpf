// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Module provides API to create eBPF programs by Rust programming language

use ebpf::Insn;

/// Represents single eBPF instruction
pub trait Instruction: Sized {
    /// returns instruction opt code
    fn opt_code_byte(&self) -> u8;

    /// returns destination register
    fn dst(&self) -> u8;

    /// returns source register
    fn src(&self) -> u8;

    /// returns offset bytes
    fn offset(&self) -> i16;

    /// returns immediate value
    fn imm(&self) -> i32;

    /// sets destination register
    fn dst_reg(self, dst: u8) -> Self;

    /// sets source register
    fn src_reg(self, src: u8) -> Self;

    /// sets offset bytes
    fn offset_bytes(self, offset: i16) -> Self;

    /// sets immediate value
    fn immediate(self, imm: i32) -> Self;
}

pub trait IntoBytes {
    type Bytes;

    fn into_bytes(self) -> Self::Bytes;
}

impl<'i, I: Instruction> IntoBytes for &'i I {
    type Bytes = Vec<u8>;

    fn into_bytes(self) -> Self::Bytes {
        let mut buffer = Vec::with_capacity(8);
        buffer.push(self.opt_code_byte());
        buffer.push(self.src() << 4 | self.dst());
        buffer.push((self.offset() & 0x00_ff) as u8);
        buffer.push(((self.offset() & 0xff_00) >> 8) as u8);
        buffer.push((self.imm() & 0x00_00_00_ff) as u8);
        buffer.push(((self.imm() & 0x00_00_ff_00) >> 8) as u8);
        buffer.push(((self.imm() & 0x00_ff_00_00) >> 16) as u8);
        buffer.push(((self.imm() & 0xff_00_00_00) >> 24) as u8);
        buffer
    }
}

/// BPF instruction stack in byte representation
pub struct BpfCode {
    instructions: Vec<u8>
}

impl BpfCode {

    pub fn new() -> Self {
        BpfCode { instructions: vec![] }
    }

    pub fn mov_add(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::Add)
    }

    pub fn mov_sub(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::Sub)
    }

    pub fn mov_mul(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::Mul)
    }

    pub fn mov_div(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::Div)
    }

    pub fn mov_bit_or(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::BitOr)
    }

    pub fn mov_bit_and(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::BitAnd)
    }

    pub fn mov_left_shift(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::LShift)
    }

    pub fn mov_right_shift(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::RShift)
    }

    pub fn mov_negate(&mut self, arch: Arch) -> Move {
        self.mov_internal(Source::Imm, arch, OpBits::Negate)
    }

    pub fn mov_mod(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::Mod)
    }

    pub fn mov_bit_xor(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::BitXor)
    }

    pub fn mov(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::NoOp)
    }

    pub fn mov_signed_right_shift(&mut self, source: Source, arch: Arch) -> Move {
        self.mov_internal(source, arch, OpBits::SignRShift)
    }

    #[inline]
    fn mov_internal(&mut self, source: Source, arch_bits: Arch, op_bits: OpBits) -> Move {
        Move {
            bpf_code: self,
            src_bit: source,
            op_bits: op_bits,
            arch_bits: arch_bits,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn swap_bytes(&mut self, endian: Endian) -> SwapBytes {
        SwapBytes {
            bpf_code: self,
            endian: endian,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn load(&mut self, mem_size: MemSize) -> Load {
        self.load_internal(mem_size, Addressing::Undef, 0x00)
    }

    pub fn load_abs(&mut self, mem_size: MemSize) -> Load {
        self.load_internal(mem_size, Addressing::Abs, 0x00)
    }

    pub fn load_ind(&mut self, mem_size: MemSize) -> Load {
        self.load_internal(mem_size, Addressing::Ind, 0x00)
    }

    pub fn load_x(&mut self, mem_size: MemSize) -> Load {
        self.load_internal(mem_size, Addressing::Undef, 0x61)
    }

    #[inline]
    fn load_internal(&mut self, mem_size: MemSize, addressing: Addressing, source: u8) -> Load {
        Load {
            bpf_code: self,
            addressing: addressing,
            mem_size: mem_size,
            source: source,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn store(&mut self, mem_size: MemSize) -> Store {
        self.store_internal(mem_size, 0x00)
    }

    pub fn store_x(&mut self, mem_size: MemSize) -> Store {
        self.store_internal(mem_size, 0x61)
    }

    #[inline]
    fn store_internal(&mut self, mem_size: MemSize, source: u8) -> Store {
        Store {
            bpf_code: self,
            mem_size: mem_size,
            source: source,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn jump_unconditional(&mut self) -> Jump {
        self.jump_conditional(Cond::Abs, Source::Imm)
    }

    pub fn jump_conditional(&mut self, cond: Cond, src_bit: Source) -> Jump {
        Jump {
            bpf_code: self,
            cond: cond,
            src_bit: src_bit,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn call(&mut self) -> FunctionCall {
        FunctionCall {
            bpf_code: self,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }

    pub fn exit(&mut self) -> Exit {
        Exit {
            bpf_code: self,
            insn: Insn {
                opc: 0x00,
                dst: 0x00,
                src: 0x00,
                off: 0x00_00,
                imm: 0x00_00_00_00
            }
        }
    }
}

impl<'a> IntoBytes for &'a BpfCode {
    type Bytes = &'a [u8];

    fn into_bytes(self) -> Self::Bytes {
        self.instructions.as_slice()
    }
}

pub struct Move<'i> {
    bpf_code: &'i mut BpfCode,
    src_bit: Source,
    op_bits: OpBits,
    arch_bits: Arch,
    insn: Insn
}

impl<'i> Move<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for Move<'i> {
    fn opt_code_byte(&self) -> u8 {
        let op_bits = self.op_bits as u8;
        let src_bit = self.src_bit as u8;
        let arch_bits = self.arch_bits as u8;
        op_bits | src_bit | arch_bits
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum Source {
    /// immediate field will be used as a source
    Imm = 0x00,
    /// src register will be used as a source
    Reg = 0x08
}

#[derive(Copy, Clone)]
enum OpBits {
    Add = 0x00,
    Sub = 0x10,
    Mul = 0x20,
    Div = 0x30,
    BitOr = 0x40,
    BitAnd = 0x50,
    LShift = 0x60,
    RShift = 0x70,
    Negate = 0x80,
    Mod = 0x90,
    BitXor = 0xa0,
    NoOp = 0xb0,
    SignRShift = 0xc0
}

#[derive(Copy, Clone)]
pub enum Arch {
    X64 = 0x07,
    X32 = 0x04
}

pub struct SwapBytes<'i> {
    bpf_code: &'i mut BpfCode,
    endian: Endian,
    insn: Insn
}

impl<'i> SwapBytes<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for SwapBytes<'i> {
    fn opt_code_byte(&self) -> u8 {
        self.endian as u8
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

#[derive(Copy, Clone)]
pub enum Endian {
    Little = 0xd4,
    Big = 0xdc
}

pub struct Load<'i> {
    bpf_code: &'i mut BpfCode,
    addressing: Addressing,
    mem_size: MemSize,
    source: u8,
    insn: Insn
}

impl<'i> Load<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for Load<'i> {
    fn opt_code_byte(&self) -> u8 {
        let size = self.mem_size as u8;
        let addressing = self.addressing as u8;
        addressing | size | self.source
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

pub struct Store<'i> {
    bpf_code: &'i mut BpfCode,
    mem_size: MemSize,
    source: u8,
    insn: Insn
}

impl<'i> Store<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for Store<'i> {
    fn opt_code_byte(&self) -> u8 {
        let size = self.mem_size as u8;
        0x62 | size | self.source
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

#[derive(Copy, Clone)]
pub enum MemSize {
    DoubleWord = 0x18,
    Byte = 0x10,
    HalfWord = 0x08,
    Word = 0x00
}

#[derive(Copy, Clone)]
enum Addressing {
    Undef = 0x00,
    Abs = 0x20,
    Ind = 0x40
}

pub struct Jump<'i> {
    bpf_code: &'i mut BpfCode,
    cond: Cond,
    src_bit: Source,
    insn: Insn
}

impl<'i> Jump<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for Jump<'i> {
    fn opt_code_byte(&self) -> u8 {
        let cmp: u8 = self.cond as u8;
        let src_bit = self.src_bit as u8;
        cmp | src_bit | 0x05
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum Cond {
    Abs = 0x00,
    Equals = 0x10,
    Greater = 0x20,
    GreaterEquals = 0x30,
    BitAnd = 0x40,
    NotEquals = 0x50,
    GreaterSigned = 0x60,
    GreaterEqualsSigned = 0x70
}

pub struct FunctionCall<'i> {
    bpf_code: &'i mut BpfCode,
    insn: Insn
}

impl<'i> FunctionCall<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for FunctionCall<'i> {
    fn opt_code_byte(&self) -> u8 {
        0x85
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

pub struct Exit<'i> {
    bpf_code: &'i mut BpfCode,
    insn: Insn
}

impl<'i> Exit<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.into_bytes();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Instruction for Exit<'i> {
    fn opt_code_byte(&self) -> u8 {
        0x95
    }

    fn dst(&self) -> u8 {
        self.insn.dst
    }

    fn src(&self) -> u8 {
        self.insn.src
    }

    fn offset(&self) -> i16 {
        self.insn.off
    }

    fn imm(&self) -> i32 {
        self.insn.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.insn.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.insn.src = src;
        self
    }

    fn offset_bytes(mut self, offset: i16) -> Self {
        self.insn.off = offset;
        self
    }

    fn immediate(mut self, imm: i32) -> Self {
        self.insn.imm = imm;
        self
    }
}

#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod special {
        use super::super::*;

        #[test]
        fn call_immediate() {
            let mut program = BpfCode::new();
            program.call().immediate(0x11_22_33_44).push();

            assert_eq!(program.into_bytes(), &[0x85, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn exit_operation() {
            let mut program = BpfCode::new();
            program.exit().push();

            assert_eq!(program.into_bytes(), &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
    }

    #[cfg(test)]
    mod jump_instructions {
        #[cfg(test)]
        mod register {
            use super::super::super::*;

            #[test]
            fn jump_on_dst_equals_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Equals, Source::Reg).dst_reg(0x01).src_reg(0x02).push();

                assert_eq!(program.into_bytes(), &[0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Greater, Source::Reg).dst_reg(0x03).src_reg(0x02).push();

                assert_eq!(program.into_bytes(), &[0x2d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEquals, Source::Reg).dst_reg(0x04).src_reg(0x01).push();

                assert_eq!(program.into_bytes(), &[0x3d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_src_not_equal_zero() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::BitAnd, Source::Reg).dst_reg(0x05).src_reg(0x02).push();

                assert_eq!(program.into_bytes(), &[0x4d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::NotEquals, Source::Reg).dst_reg(0x03).src_reg(0x05).push();

                assert_eq!(program.into_bytes(), &[0x5d, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterSigned, Source::Reg).dst_reg(0x04).src_reg(0x01).push();

                assert_eq!(program.into_bytes(), &[0x6d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEqualsSigned, Source::Reg).dst_reg(0x01).src_reg(0x03).push();

                assert_eq!(program.into_bytes(), &[0x7d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn jump_to_label() {
                let mut program = BpfCode::new();
                program.jump_unconditional().offset_bytes(0x00_11).push();

                assert_eq!(program.into_bytes(), &[0x05, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_equals_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Equals, Source::Imm).dst_reg(0x01).immediate(0x00_11_22_33).push();

                assert_eq!(program.into_bytes(), &[0x15, 0x01, 0x00, 0x00, 0x33, 0x22, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Greater, Source::Imm).dst_reg(0x02).immediate(0x00_11_00_11).push();

                assert_eq!(program.into_bytes(), &[0x25, 0x02, 0x00, 0x00, 0x11, 0x00, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEquals, Source::Imm).dst_reg(0x04).immediate(0x00_22_11_00).push();

                assert_eq!(program.into_bytes(), &[0x35, 0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_const_not_equal_zero() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::BitAnd, Source::Imm).dst_reg(0x05).push();

                assert_eq!(program.into_bytes(), &[0x45, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::NotEquals, Source::Imm).dst_reg(0x03).push();

                assert_eq!(program.into_bytes(), &[0x55, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterSigned, Source::Imm).dst_reg(0x04).push();

                assert_eq!(program.into_bytes(), &[0x65, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEqualsSigned, Source::Imm).dst_reg(0x01).push();

                assert_eq!(program.into_bytes(), &[0x75, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }
    }

    #[cfg(test)]
    mod store_instructions {
        use super::super::*;

        #[test]
        fn store_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::Word).dst_reg(0x01).offset_bytes(0x00_11).immediate(0x11_22_33_44).push();

            assert_eq!(program.into_bytes(), &[0x62, 0x01, 0x11, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn store_half_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::HalfWord).dst_reg(0x02).offset_bytes(0x11_22).push();

            assert_eq!(program.into_bytes(), &[0x6a, 0x02, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::Byte).push();

            assert_eq!(program.into_bytes(), &[0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::DoubleWord).push();

            assert_eq!(program.into_bytes(), &[0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::Word).dst_reg(0x01).src_reg(0x02).push();

            assert_eq!(program.into_bytes(), &[0x63, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_half_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::HalfWord).push();

            assert_eq!(program.into_bytes(), &[0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::Byte).push();

            assert_eq!(program.into_bytes(), &[0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::DoubleWord).push();

            assert_eq!(program.into_bytes(), &[0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
    }

    #[cfg(test)]
    mod load_instructions {
        #[cfg(test)]
        mod register {
            use super::super::super::*;

            #[test]
            fn load_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::Word).dst_reg(0x01).src_reg(0x02).offset_bytes(0x00_02).push();

                assert_eq!(program.into_bytes(), &[0x61, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_half_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::HalfWord).dst_reg(0x02).src_reg(0x01).offset_bytes(0x11_22).push();

                assert_eq!(program.into_bytes(), &[0x69, 0x12, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_byte_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::Byte).dst_reg(0x01).src_reg(0x04).offset_bytes(0x00_11).push();

                assert_eq!(program.into_bytes(), &[0x71, 0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_double_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::DoubleWord).dst_reg(0x04).src_reg(0x05).offset_bytes(0x44_55).push();

                assert_eq!(program.into_bytes(), &[0x79, 0x54, 0x55, 0x44, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn load_double_word() {
                let mut program = BpfCode::new();
                program.load(MemSize::DoubleWord).dst_reg(0x01).immediate(0x00_01_02_03).push();

                assert_eq!(program.into_bytes(), &[0x18, 0x01, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
            }

            #[test]
            fn load_abs_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::Word).push();

                assert_eq!(program.into_bytes(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_half_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::HalfWord).dst_reg(0x05).push();

                assert_eq!(program.into_bytes(), &[0x28, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_byte() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::Byte).dst_reg(0x01).push();

                assert_eq!(program.into_bytes(), &[0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_double_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::DoubleWord).dst_reg(0x01).immediate(0x01_02_03_04).push();

                assert_eq!(program.into_bytes(), &[0x38, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
            }

            #[test]
            fn load_indirect_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::Word).push();

                assert_eq!(program.into_bytes(), &[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_half_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::HalfWord).push();

                assert_eq!(program.into_bytes(), &[0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_byte() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::Byte).push();

                assert_eq!(program.into_bytes(), &[0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_double_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::DoubleWord).push();

                assert_eq!(program.into_bytes(), &[0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }
    }

    #[cfg(test)]
    mod byte_swap_instructions {
        use super::super::*;

        #[test]
        fn convert_host_to_little_endian_16bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Little).dst_reg(0x01).immediate(0x00_00_00_10).push();

            assert_eq!(program.into_bytes(), &[0xd4, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_32bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Little).dst_reg(0x02).immediate(0x00_00_00_20).push();

            assert_eq!(program.into_bytes(), &[0xd4, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_64bit() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Little).dst_reg(0x03).immediate(0x00_00_00_40).push();

            assert_eq!(program.into_bytes(), &[0xd4, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_16bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x01).immediate(0x00_00_00_10).push();

            assert_eq!(program.into_bytes(), &[0xdc, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_32bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x02).immediate(0x00_00_00_20).push();

            assert_eq!(program.into_bytes(), &[0xdc, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_64bit() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x03).immediate(0x00_00_00_40).push();

            assert_eq!(program.into_bytes(), &[0xdc, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
        }
    }

    #[cfg(test)]
    mod moves_instructions {
        #[cfg(test)]
        mod arch_x64 {
            #[cfg(test)]
            mod immediate {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x01_02_03_04).push();

                    assert_eq!(program.into_bytes(), &[0x07, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Imm, Arch::X64).dst_reg(0x04).immediate(0x00_01_02_03).push();

                    assert_eq!(program.into_bytes(), &[0x17, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Imm, Arch::X64).dst_reg(0x05).immediate(0x04_03_02_01).push();

                    assert_eq!(program.into_bytes(), &[0x27, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x00_ff_00_ff).push();

                    assert_eq!(program.into_bytes(), &[0x37, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x00_11_00_22).push();

                    assert_eq!(program.into_bytes(), &[0x47, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x11_22_33_44).push();

                    assert_eq!(program.into_bytes(), &[0x57, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Imm, Arch::X64).dst_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x67, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Imm, Arch::X64).dst_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x77, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.mov_negate(Arch::X64).dst_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Imm, Arch::X64).dst_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x97, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Imm, Arch::X64).dst_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0xa7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Imm, Arch::X64).dst_reg(0x01).immediate(0x00_00_00_FF).push();

                    assert_eq!(program.into_bytes(), &[0xb7, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Imm, Arch::X64).dst_reg(0x05).push();

                    assert_eq!(program.into_bytes(), &[0xc7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x0f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0x1f, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Reg, Arch::X64).dst_reg(0x04).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0x2f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Reg, Arch::X64).dst_reg(0x01).src_reg(0x00).push();

                    assert_eq!(program.into_bytes(), &[0x3f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x4f, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x5f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0x6f, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0x7f, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Reg, Arch::X64).dst_reg(0x01).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x9f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0xaf, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Reg, Arch::X64).src_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0xcf, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }
        }

        #[cfg(test)]
        mod arch_x32 {
            #[cfg(test)]
            mod immediate {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x01_02_03_04).push();

                    assert_eq!(program.into_bytes(), &[0x04, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Imm, Arch::X32).dst_reg(0x04).immediate(0x00_01_02_03).push();

                    assert_eq!(program.into_bytes(), &[0x14, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Imm, Arch::X32).dst_reg(0x05).immediate(0x04_03_02_01).push();

                    assert_eq!(program.into_bytes(), &[0x24, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x00_ff_00_ff).push();

                    assert_eq!(program.into_bytes(), &[0x34, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x00_11_00_22).push();

                    assert_eq!(program.into_bytes(), &[0x44, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x11_22_33_44).push();

                    assert_eq!(program.into_bytes(), &[0x54, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Imm, Arch::X32).dst_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Imm, Arch::X32).dst_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.mov_negate(Arch::X32).dst_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x84, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Imm, Arch::X32).dst_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x94, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Imm, Arch::X32).dst_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0xa4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Imm, Arch::X32).dst_reg(0x01).immediate(0x00_00_00_FF).push();

                    assert_eq!(program.into_bytes(), &[0xb4, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Imm, Arch::X32).dst_reg(0x05).push();

                    assert_eq!(program.into_bytes(), &[0xc4, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x0c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0x1c, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Reg, Arch::X32).dst_reg(0x04).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0x2c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Reg, Arch::X32).dst_reg(0x01).src_reg(0x00).push();

                    assert_eq!(program.into_bytes(), &[0x3c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0x4c, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x5c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0x6c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0x7c, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Reg, Arch::X32).dst_reg(0x01).src_reg(0x02).push();

                    assert_eq!(program.into_bytes(), &[0x9c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.into_bytes(), &[0xac, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Reg, Arch::X32).dst_reg(0x00).src_reg(0x01).push();

                    assert_eq!(program.into_bytes(), &[0xbc, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.into_bytes(), &[0xcc, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }
        }
    }
}
