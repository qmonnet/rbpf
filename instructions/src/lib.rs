use std::fmt;

//the copy of rbpf::ebpf::Insn
#[derive(Debug, PartialEq)]
pub struct Insn {
    pub opc: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

pub trait Instruction: Sized {
    fn opt_code_byte(&self) -> u8;

    fn dst(&self) -> u8;

    fn src(&self) -> u8;

    fn offset(&self) -> i16;

    fn imm(&self) -> i32;

    fn dst_reg(self, dst: u8) -> Self;

    fn src_reg(self, src: u8) -> Self;

    fn offset_bytes(self, offset: i16) -> Self;

    fn immediate(self, imm: i32) -> Self;
}

pub trait Assemble {
    type Asm;

    fn assemble(self) -> Self::Asm;
}

pub trait Disassemble {
    fn disassemble(&self) -> String;
}

impl<'i, I: Instruction> Assemble for &'i I {
    type Asm = Vec<u8>;

    fn assemble(self) -> Self::Asm {
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

pub struct BpfCode {
    instructions: Vec<u8>
}

//todo: rename to raw bpf code
impl BpfCode {

//    pub fn parse(src: String) -> Self {
//      todo: parse string into instructions
//    }

//    pub fn from_elf(src: Path) -> Self {
//        todo: create from elf
//    }

//    pub fn verify(self) -> VerifiedBpfCode {
//        todo: impl verification
//    }

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

//todo: create VerifiedBpfCode and move impl to it
impl<'a> Assemble for &'a BpfCode {
    type Asm = &'a [u8];

    fn assemble(self) -> Self::Asm {
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
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for Move<'i> {
    fn disassemble(&self) -> String {
        let source = if self.src_bit == Source::Reg {
            format!("r{}", self.src())
        } else {
            format!("{:#x}", self.imm())
        };
        format!("{:?}{:?} r{}, {}", self.op_bits, self.arch_bits, self.dst(), source)
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
    Imm = 0x00,
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

impl fmt::Debug for OpBits {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OpBits::Add => write!(f, "add"),
            OpBits::Sub => write!(f, "sub"),
            OpBits::Mul => write!(f, "mul"),
            OpBits::Div => write!(f, "div"),
            OpBits::BitOr => write!(f, "or"),
            OpBits::BitAnd => write!(f, "and"),
            OpBits::LShift => write!(f, "lsh"),
            OpBits::RShift => write!(f, "rsh"),
            OpBits::Negate => write!(f, "neg"),
            OpBits::Mod => write!(f, "mod"),
            OpBits::BitXor => write!(f, "xor"),
            OpBits::NoOp => write!(f, "mov"),
            OpBits::SignRShift => write!(f, "arsh"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum Arch {
    X64 = 0x07,
    X32 = 0x04
}

impl fmt::Debug for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Arch::X64 => write!(f, "64"),
            Arch::X32 => write!(f, "32")
        }
    }
}

pub struct SwapBytes<'i> {
    bpf_code: &'i mut BpfCode,
    endian: Endian,
    insn: Insn
}

impl<'i> SwapBytes<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for SwapBytes<'i> {
    fn disassemble(&self) -> String {
        format!("{:?}{:?} r{:?}", self.endian, self.imm(), self.dst())
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

impl fmt::Debug for Endian {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Endian::Big => write!(f, "be"),
            Endian::Little => write!(f, "le")
        }
    }
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
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for Load<'i> {
    fn disassemble(&self) -> String {
        if self.source == 0x61 {
            format!("ldx{:?} r{}, [r{}+{:#x}]", self.mem_size, self.dst(), self.src(), self.offset())
        } else {
            format!("ld{:?}{:?} r{}, [r{}+{:#x}]", self.addressing, self.mem_size, self.dst(), self.src(), self.offset())
        }
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
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for Store<'i> {
    fn disassemble(&self) -> String {
        if self.source == 0x61 {
            format!("stx{:?} [r{}+{:#x}], r{}", self.mem_size, self.dst(), self.offset(), self.src())
        } else {
            format!("st{:?} [r{}+{:#x}], {:#x}", self.mem_size, self.dst(), self.offset(), self.imm())
        }
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

impl fmt::Debug for MemSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MemSize::DoubleWord => write!(f, "dw"),
            MemSize::Byte => write!(f, "b"),
            MemSize::HalfWord => write!(f, "hw"),
            MemSize::Word => write!(f, "w")
        }
    }
}

#[derive(Copy, Clone)]
enum Addressing {
    Undef = 0x00,
    Abs = 0x20,
    Ind = 0x40
}

impl fmt::Debug for Addressing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Addressing::Undef => write!(f, ""),
            Addressing::Abs => write!(f, "abs"),
            Addressing::Ind => write!(f, "ind"),
        }
    }
}

pub struct Jump<'i> {
    bpf_code: &'i mut BpfCode,
    cond: Cond,
    src_bit: Source,
    insn: Insn
}

impl<'i> Jump<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for Jump<'i> {
    fn disassemble(&self) -> String {
        if self.cond == Cond::Abs {
            format!("ja {:+#x}", self.offset())
        } else if self.src_bit == Source::Reg {
            format!("j{:?} r{}, r{}, {:+#x}", self.cond, self.dst(), self.src(), self.offset())
        } else {
            format!("j{:?} r{}, {:#x}, {:+#x}", self.cond, self.dst(), self.imm(), self.offset())
        }
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

impl fmt::Debug for Cond {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cond::Abs => write!(f, "a"),
            Cond::Equals => write!(f, "eq"),
            Cond::Greater => write!(f, "gt"),
            Cond::GreaterEquals => write!(f, "ge"),
            Cond::BitAnd => write!(f, "set"),
            Cond::NotEquals => write!(f, "ne"),
            Cond::GreaterSigned => write!(f, "sgt"),
            Cond::GreaterEqualsSigned => write!(f, "sge")
        }
    }
}

pub struct FunctionCall<'i> {
    bpf_code: &'i mut BpfCode,
    insn: Insn
}

impl<'i> FunctionCall<'i> {
    pub fn push(mut self) -> &'i mut BpfCode {
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for FunctionCall<'i> {
    fn disassemble(&self) -> String {
        "call".to_owned()
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
        let mut asm = self.assemble();
        self.bpf_code.instructions.append(&mut asm);
        self.bpf_code
    }
}

impl<'i> Disassemble for Exit<'i> {
    fn disassemble(&self) -> String {
        "exit".to_owned()
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
    mod disassembling {
        use super::super::*;
        
        #[test]
        fn exit() {
            let mut program = BpfCode::new();
            
            let exit = program.exit();

            assert_eq!(exit.disassemble(), "exit");
        }

        #[test]
        fn call() {
            let mut program = BpfCode::new();

            let call = program.call();

            assert_eq!(call.disassemble(), "call");
        }
        
        #[cfg(test)]
        mod jump_instructions {
            use super::super::super::*;

            #[test]
            fn jump_unconditional() {
                let mut program = BpfCode::new();

                let jmp = program.jump_unconditional();

                assert_eq!(jmp.disassemble(), "ja +0x0");
            }

            #[test]
            fn jump_conditional_reg() {
                let mut program = BpfCode::new();

                let jmp = program.jump_conditional(Cond::Equals, Source::Reg).dst_reg(0x01).src_reg(0x02).offset_bytes(0x00_01);

                assert_eq!(jmp.disassemble(), "jeq r1, r2, +0x1");
            }

            #[test]
            fn jump_conditional_imm() {
                let mut program = BpfCode::new();

                let jmp = program.jump_conditional(Cond::NotEquals, Source::Imm).dst_reg(0x03).immediate(0x00_00_00_11).offset_bytes(0x00_02);

                assert_eq!(jmp.disassemble(), "jne r3, 0x11, +0x2");
            }
        }

        #[cfg(test)]
        mod store_instructions {
            use super::super::super::*;

            #[test]
            fn store_byte_from_register() {
                let mut program = BpfCode::new();

                let store_x = program.store_x(MemSize::Byte);

                assert_eq!(store_x.disassemble(), "stxb [r0+0x0], r0");
            }

            #[test]
            fn store_word_from_register() {
                let mut program = BpfCode::new();

                let store_x = program.store_x(MemSize::Word);

                assert_eq!(store_x.disassemble(), "stxw [r0+0x0], r0");
            }

            #[test]
            fn store_into_destination_reg() {
                let mut program = BpfCode::new();

                let store_x = program.store_x(MemSize::HalfWord).dst_reg(0x01);

                assert_eq!(store_x.disassemble(), "stxhw [r1+0x0], r0");
            }

            #[test]
            fn store_with_specified_offset() {
                let mut program = BpfCode::new();

                let store_x = program.store_x(MemSize::DoubleWord).offset_bytes(0x11_22);

                assert_eq!(store_x.disassemble(), "stxdw [r0+0x1122], r0");
            }

            #[test]
            fn store_from_source_reg() {
                let mut program = BpfCode::new();

                let store_x = program.store_x(MemSize::Byte).src_reg(0x03);

                assert_eq!(store_x.disassemble(), "stxb [r0+0x0], r3");
            }

            #[test]
            fn store_immediate() {
                let mut program = BpfCode::new();

                let store = program.store(MemSize::DoubleWord).immediate(0x00_11_22_33);

                assert_eq!(store.disassemble(), "stdw [r0+0x0], 0x112233");
            }
        }

        #[cfg(test)]
        mod load_store_instructions {
            use super::super::super::*;

            #[test]
            fn load_x_word_size() {
                let mut program = BpfCode::new();

                let load_x = program.load_x(MemSize::Word);

                assert_eq!(load_x.disassemble(), "ldxw r0, [r0+0x0]");
            }

            #[test]
            fn load_x_byte_size() {
                let mut program = BpfCode::new();

                let load_x = program.load_x(MemSize::Byte);

                assert_eq!(load_x.disassemble(), "ldxb r0, [r0+0x0]");
            }

            #[test]
            fn load_from_src() {
                let mut program = BpfCode::new();

                let load_x = program.load_x(MemSize::DoubleWord).src_reg(0x03);

                assert_eq!(load_x.disassemble(), "ldxdw r0, [r3+0x0]");
            }

            #[test]
            fn load_with_offset() {
                let mut program = BpfCode::new();

                let load_x = program.load_x(MemSize::HalfWord).offset_bytes(0x11_22);

                assert_eq!(load_x.disassemble(), "ldxhw r0, [r0+0x1122]");
            }

            #[test]
            fn load_from_dst_register() {
                let mut program = BpfCode::new();

                let load_x = program.load_x(MemSize::Byte).dst_reg(0x01);

                assert_eq!(load_x.disassemble(), "ldxb r1, [r0+0x0]");
            }

            #[test]
            fn indirect_load() {
                let mut program = BpfCode::new();

                let indirect = program.load_ind(MemSize::DoubleWord);

                assert_eq!(indirect.disassemble(), "ldinddw r0, [r0+0x0]");
            }
        }

        #[cfg(test)]
        mod swap_bytes_instructions {
            use super::super::super::*;

            #[test]
            fn swap_little_endings() {
                let mut program = BpfCode::new();

                let swap = program.swap_bytes(Endian::Little).immediate(0x00_00_00_10);

                assert_eq!(swap.disassemble(), "le16 r0");
            }

            #[test]
            fn swap_big_endings() {
                let mut program = BpfCode::new();

                let swap = program.swap_bytes(Endian::Big).immediate(0x00_00_00_10);

                assert_eq!(swap.disassemble(), "be16 r0");
            }

            #[test]
            fn swap_bits_size() {
                let mut program = BpfCode::new();

                let swap = program.swap_bytes(Endian::Big).immediate(0x00_00_00_20);

                assert_eq!(swap.disassemble(), "be32 r0");
            }

            #[test]
            fn swap_destination_register() {
                let mut program = BpfCode::new();

                let swap = program.swap_bytes(Endian::Little).dst_reg(0x03).immediate(0x00_00_00_20);

                assert_eq!(swap.disassemble(), "le32 r3");
            }
        }

        #[cfg(test)]
        mod move_instructions {
            use super::super::super::*;

            #[test]
            fn disassemble_x64_register_to_register_move_add() {
                let mut program = BpfCode::new();

                let mov_add = program.mov_add(Source::Reg, Arch::X64).dst_reg(0x01).src_reg(0x02);

                assert_eq!(mov_add.disassemble(), "add64 r1, r2");
            }

            #[test]
            fn disassemble_x32_register_to_register_move_add() {
                let mut program = BpfCode::new();

                let move_add = program.mov_add(Source::Reg, Arch::X32).dst_reg(0x01).src_reg(0x02);

                assert_eq!(move_add.disassemble(), "add32 r1, r2");
            }

            #[test]
            fn disassemble_move_sub() {
                let mut program = BpfCode::new();

                let move_sub = program.mov_sub(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x03);

                assert_eq!(move_sub.disassemble(), "sub64 r2, r3");
            }

            #[test]
            fn disassemble_move_from_immediate() {
                let mut program = BpfCode::new();

                let move_imm = program.mov(Source::Imm, Arch::X64).dst_reg(0x03).immediate(0x12_34_56_78);

                assert_eq!(move_imm.disassemble(), "mov64 r3, 0x12345678");
            }
        }
    }

    #[cfg(test)]
    mod special {
        use super::super::*;

        #[test]
        fn call_immediate() {
            let mut program = BpfCode::new();
            program.call().immediate(0x11_22_33_44).push();

            assert_eq!(program.assemble(), &[0x85, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn exit_operation() {
            let mut program = BpfCode::new();
            program.exit().push();

            assert_eq!(program.assemble(), &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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

                assert_eq!(program.assemble(), &[0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Greater, Source::Reg).dst_reg(0x03).src_reg(0x02).push();

                assert_eq!(program.assemble(), &[0x2d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEquals, Source::Reg).dst_reg(0x04).src_reg(0x01).push();

                assert_eq!(program.assemble(), &[0x3d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_src_not_equal_zero() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::BitAnd, Source::Reg).dst_reg(0x05).src_reg(0x02).push();

                assert_eq!(program.assemble(), &[0x4d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_src() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::NotEquals, Source::Reg).dst_reg(0x03).src_reg(0x05).push();

                assert_eq!(program.assemble(), &[0x5d, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterSigned, Source::Reg).dst_reg(0x04).src_reg(0x01).push();

                assert_eq!(program.assemble(), &[0x6d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEqualsSigned, Source::Reg).dst_reg(0x01).src_reg(0x03).push();

                assert_eq!(program.assemble(), &[0x7d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn jump_to_label() {
                let mut program = BpfCode::new();
                program.jump_unconditional().offset_bytes(0x00_11).push();

                assert_eq!(program.assemble(), &[0x05, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_equals_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Equals, Source::Imm).dst_reg(0x01).immediate(0x00_11_22_33).push();

                assert_eq!(program.assemble(), &[0x15, 0x01, 0x00, 0x00, 0x33, 0x22, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::Greater, Source::Imm).dst_reg(0x02).immediate(0x00_11_00_11).push();

                assert_eq!(program.assemble(), &[0x25, 0x02, 0x00, 0x00, 0x11, 0x00, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEquals, Source::Imm).dst_reg(0x04).immediate(0x00_22_11_00).push();

                assert_eq!(program.assemble(), &[0x35, 0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_const_not_equal_zero() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::BitAnd, Source::Imm).dst_reg(0x05).push();

                assert_eq!(program.assemble(), &[0x45, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_const() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::NotEquals, Source::Imm).dst_reg(0x03).push();

                assert_eq!(program.assemble(), &[0x55, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterSigned, Source::Imm).dst_reg(0x04).push();

                assert_eq!(program.assemble(), &[0x65, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.jump_conditional(Cond::GreaterEqualsSigned, Source::Imm).dst_reg(0x01).push();

                assert_eq!(program.assemble(), &[0x75, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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

            assert_eq!(program.assemble(), &[0x62, 0x01, 0x11, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn store_half_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::HalfWord).dst_reg(0x02).offset_bytes(0x11_22).push();

            assert_eq!(program.assemble(), &[0x6a, 0x02, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::Byte).push();

            assert_eq!(program.assemble(), &[0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.store(MemSize::DoubleWord).push();

            assert_eq!(program.assemble(), &[0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::Word).dst_reg(0x01).src_reg(0x02).push();

            assert_eq!(program.assemble(), &[0x63, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_half_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::HalfWord).push();

            assert_eq!(program.assemble(), &[0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::Byte).push();

            assert_eq!(program.assemble(), &[0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.store_x(MemSize::DoubleWord).push();

            assert_eq!(program.assemble(), &[0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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

                assert_eq!(program.assemble(), &[0x61, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_half_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::HalfWord).dst_reg(0x02).src_reg(0x01).offset_bytes(0x11_22).push();

                assert_eq!(program.assemble(), &[0x69, 0x12, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_byte_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::Byte).dst_reg(0x01).src_reg(0x04).offset_bytes(0x00_11).push();

                assert_eq!(program.assemble(), &[0x71, 0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_double_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.load_x(MemSize::DoubleWord).dst_reg(0x04).src_reg(0x05).offset_bytes(0x44_55).push();

                assert_eq!(program.assemble(), &[0x79, 0x54, 0x55, 0x44, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn load_double_word() {
                let mut program = BpfCode::new();
                program.load(MemSize::DoubleWord).dst_reg(0x01).immediate(0x00_01_02_03).push();

                assert_eq!(program.assemble(), &[0x18, 0x01, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
            }

            #[test]
            fn load_abs_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::Word).push();

                assert_eq!(program.assemble(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_half_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::HalfWord).dst_reg(0x05).push();

                assert_eq!(program.assemble(), &[0x28, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_byte() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::Byte).dst_reg(0x01).push();

                assert_eq!(program.assemble(), &[0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_double_word() {
                let mut program = BpfCode::new();
                program.load_abs(MemSize::DoubleWord).dst_reg(0x01).immediate(0x01_02_03_04).push();

                assert_eq!(program.assemble(), &[0x38, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
            }

            #[test]
            fn load_indirect_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::Word).push();

                assert_eq!(program.assemble(), &[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_half_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::HalfWord).push();

                assert_eq!(program.assemble(), &[0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_byte() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::Byte).push();

                assert_eq!(program.assemble(), &[0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_double_word() {
                let mut program = BpfCode::new();
                program.load_ind(MemSize::DoubleWord).push();

                assert_eq!(program.assemble(), &[0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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

            assert_eq!(program.assemble(), &[0xd4, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_32bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Little).dst_reg(0x02).immediate(0x00_00_00_20).push();

            assert_eq!(program.assemble(), &[0xd4, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_64bit() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Little).dst_reg(0x03).immediate(0x00_00_00_40).push();

            assert_eq!(program.assemble(), &[0xd4, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_16bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x01).immediate(0x00_00_00_10).push();

            assert_eq!(program.assemble(), &[0xdc, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_32bits() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x02).immediate(0x00_00_00_20).push();

            assert_eq!(program.assemble(), &[0xdc, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_64bit() {
            let mut program = BpfCode::new();
            program.swap_bytes(Endian::Big).dst_reg(0x03).immediate(0x00_00_00_40).push();

            assert_eq!(program.assemble(), &[0xdc, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
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

                    assert_eq!(program.assemble(), &[0x07, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Imm, Arch::X64).dst_reg(0x04).immediate(0x00_01_02_03).push();

                    assert_eq!(program.assemble(), &[0x17, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Imm, Arch::X64).dst_reg(0x05).immediate(0x04_03_02_01).push();

                    assert_eq!(program.assemble(), &[0x27, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x00_ff_00_ff).push();

                    assert_eq!(program.assemble(), &[0x37, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x00_11_00_22).push();

                    assert_eq!(program.assemble(), &[0x47, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Imm, Arch::X64).dst_reg(0x02).immediate(0x11_22_33_44).push();

                    assert_eq!(program.assemble(), &[0x57, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Imm, Arch::X64).dst_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x67, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Imm, Arch::X64).dst_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x77, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.mov_negate(Arch::X64).dst_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Imm, Arch::X64).dst_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x97, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Imm, Arch::X64).dst_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0xa7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Imm, Arch::X64).dst_reg(0x01).immediate(0x00_00_00_FF).push();

                    assert_eq!(program.assemble(), &[0xb7, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Imm, Arch::X64).dst_reg(0x05).push();

                    assert_eq!(program.assemble(), &[0xc7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x0f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0x1f, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Reg, Arch::X64).dst_reg(0x04).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0x2f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Reg, Arch::X64).dst_reg(0x01).src_reg(0x00).push();

                    assert_eq!(program.assemble(), &[0x3f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x4f, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Reg, Arch::X64).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x5f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0x6f, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0x7f, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Reg, Arch::X64).dst_reg(0x01).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x9f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0xaf, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Reg, Arch::X64).src_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Reg, Arch::X64).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0xcf, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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

                    assert_eq!(program.assemble(), &[0x04, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Imm, Arch::X32).dst_reg(0x04).immediate(0x00_01_02_03).push();

                    assert_eq!(program.assemble(), &[0x14, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Imm, Arch::X32).dst_reg(0x05).immediate(0x04_03_02_01).push();

                    assert_eq!(program.assemble(), &[0x24, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x00_ff_00_ff).push();

                    assert_eq!(program.assemble(), &[0x34, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x00_11_00_22).push();

                    assert_eq!(program.assemble(), &[0x44, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Imm, Arch::X32).dst_reg(0x02).immediate(0x11_22_33_44).push();

                    assert_eq!(program.assemble(), &[0x54, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Imm, Arch::X32).dst_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Imm, Arch::X32).dst_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.mov_negate(Arch::X32).dst_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x84, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Imm, Arch::X32).dst_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x94, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Imm, Arch::X32).dst_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0xa4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Imm, Arch::X32).dst_reg(0x01).immediate(0x00_00_00_FF).push();

                    assert_eq!(program.assemble(), &[0xb4, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Imm, Arch::X32).dst_reg(0x05).push();

                    assert_eq!(program.assemble(), &[0xc4, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.mov_add(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x0c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_sub(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0x1c, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mul(Source::Reg, Arch::X32).dst_reg(0x04).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0x2c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_div(Source::Reg, Arch::X32).dst_reg(0x01).src_reg(0x00).push();

                    assert_eq!(program.assemble(), &[0x3c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_or(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0x4c, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_and(Source::Reg, Arch::X32).dst_reg(0x03).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x5c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_left_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0x6c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_right_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0x7c, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_mod(Source::Reg, Arch::X32).dst_reg(0x01).src_reg(0x02).push();

                    assert_eq!(program.assemble(), &[0x9c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_bit_xor(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x04).push();

                    assert_eq!(program.assemble(), &[0xac, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.mov(Source::Reg, Arch::X32).dst_reg(0x00).src_reg(0x01).push();

                    assert_eq!(program.assemble(), &[0xbc, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.mov_signed_right_shift(Source::Reg, Arch::X32).dst_reg(0x02).src_reg(0x03).push();

                    assert_eq!(program.assemble(), &[0xcc, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }
        }
    }
}
