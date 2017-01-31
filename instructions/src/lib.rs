pub trait Instruction: Sized {
    fn into_bytes(self) -> Vec<u8> {
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

    fn opt_code_byte(&self) -> u8;

    fn dst(&self) -> u8;

    fn src(&self) -> u8;

    fn offset(&self) -> u16;

    fn imm(&self) -> u32;

    fn dst_reg(self, dst: u8) -> Self;

    fn src_reg(self, src: u8) -> Self;

    fn offset_bytes(self, offset: u16) -> Self;

    fn immediate(self, imm: u32) -> Self;
}

pub struct BpfCode {
    instructions: Vec<u8>
}

impl BpfCode {
    pub fn new() -> Self {
        BpfCode { instructions: vec![] }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.instructions.as_slice()
    }

    pub fn add<I: Instruction>(&mut self, instruction: I) {
        let ops = instruction.into_bytes();

        for op in ops {
            self.instructions.push(op);
        }
    }
}

pub struct Move {
    src_bit: Source,
    op_bits: Op,
    arch_bits: Arch,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl Move {
    pub fn new(src_bit: Source, op_bits: Op, arch_bits: Arch) -> Self {
        Move {
            src_bit: src_bit,
            op_bits: op_bits,
            arch_bits: arch_bits,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for Move {
    fn opt_code_byte(&self) -> u8 {
        let op_bits: u8 = self.op_bits.as_ref().into();
        let src_bit: u8 = self.src_bit.as_ref().into();
        let arch_bits: u8 = self.arch_bits.as_ref().into();
        op_bits | src_bit | arch_bits
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub enum Source {
    Immediate,
    Register
}

impl AsRef<Source> for Source {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'s> From<&'s Source> for u8 {
    fn from(source: &'s Source) -> u8 {
        match *source {
            Source::Register => 0x08,
            Source::Immediate => 0x00
        }
    }
}

pub enum Op {
    NoOp,
    Add,
    Sub,
    Mul,
    Div,
    BitOr,
    BitAnd,
    LShift,
    LogicalRShift,
    Negate,
    Mod,
    BitXor,
    SignRShift
}

impl AsRef<Op> for Op {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'o> From<&'o Op> for u8 {
    fn from(op: &'o Op) -> u8 {
        match *op {
            Op::Add => 0x00,
            Op::Sub => 0x10,
            Op::Mul => 0x20,
            Op::Div => 0x30,
            Op::BitOr => 0x40,
            Op::BitAnd => 0x50,
            Op::LShift => 0x60,
            Op::LogicalRShift => 0x70,
            Op::Negate => 0x80,
            Op::Mod => 0x90,
            Op::BitXor => 0xa0,
            Op::NoOp => 0xb0,
            Op::SignRShift => 0xc0
        }
    }
}

pub enum Arch {
    X64,
    X32
}

impl AsRef<Arch> for Arch {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> From<&'a Arch> for u8 {
    fn from(arch: &'a Arch) -> u8 {
        match *arch {
            Arch::X64 => 0x07,
            Arch::X32 => 0x04
        }
    }
}

pub struct SwapBytes {
    endian: Endian,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl SwapBytes {
    pub fn new(endian: Endian) -> Self {
        SwapBytes {
            endian: endian,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for SwapBytes {
    fn opt_code_byte(&self) -> u8 {
        self.endian.as_ref().into()
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub enum Endian {
    Little,
    Big
}

impl AsRef<Endian> for Endian {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'e> From<&'e Endian> for u8 {
    fn from(endian: &'e Endian) -> u8 {
        match *endian {
            Endian::Little => 0xd4,
            Endian::Big => 0xdc
        }
    }
}

pub struct Load {
    mem_size: MemSize,
    addressing: Addressing,
    address_source: AddressSource,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl Load {
    pub fn new(mem_size: MemSize, addressing: Addressing, address_source: AddressSource) -> Self {
        Load {
            mem_size: mem_size,
            addressing: addressing,
            address_source: address_source,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for Load {
    fn opt_code_byte(&self) -> u8 {
        let addressing: u8 = self.addressing.as_ref().into();
        let size: u8 = self.mem_size.as_ref().into();
        let address_source: u8 = self.address_source.as_ref().into();
        addressing | size | address_source
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub enum MemSize {
    DoubleWord,
    Byte,
    HalfWord,
    Word
}

impl AsRef<MemSize> for MemSize {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'ms> From<&'ms MemSize> for u8 {
    fn from(mem_size: &'ms MemSize) -> u8 {
        match *mem_size {
            MemSize::DoubleWord => 0x18,
            MemSize::Byte => 0x10,
            MemSize::HalfWord => 0x08,
            MemSize::Word => 0x00
        }
    }
}

pub enum Addressing {
    Undef,
    Abs,
    Ind
}

impl AsRef<Addressing> for Addressing {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> From<&'a Addressing> for u8 {
    fn from(addressing: &'a Addressing) -> u8 {
        match *addressing {
            Addressing::Undef => 0x00,
            Addressing::Abs => 0x20,
            Addressing::Ind => 0x40
        }
    }
}

pub enum AddressSource {
    Register,
    Immediate
}

impl AsRef<AddressSource> for AddressSource {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> From<&'a AddressSource> for u8 {
    fn from(addressing: &'a AddressSource) -> u8 {
        match *addressing {
            AddressSource::Register => 0x61,
            AddressSource::Immediate => 0x00
        }
    }
}

pub struct Store {
    mem_size: MemSize,
    address_source: AddressSource,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl Store {
    pub fn new(mem_size: MemSize, address_source: AddressSource) -> Self {
        Store {
            mem_size: mem_size,
            address_source: address_source,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for Store {
    fn opt_code_byte(&self) -> u8 {
        let size: u8 = self.mem_size.as_ref().into();
        let address_source: u8 = self.address_source.as_ref().into();
        0x62 | size | address_source
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub struct Jump {
    cmp: Comparison,
    src_bit: Source,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl Jump {
    pub fn new(cmp: Comparison, src_bit: Source) -> Self {
        Jump {
            cmp: cmp,
            src_bit: src_bit,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for Jump {
    fn opt_code_byte(&self) -> u8 {
        let cmp: u8 = self.cmp.as_ref().into();
        let src_bit: u8 = self.src_bit.as_ref().into();
        cmp | src_bit | 0x05
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub enum Comparison {
    Absolute,
    Equals,
    Greater,
    GreaterEquals,
    BitAnd,
    NotEquals,
    GreaterSigned,
    GreaterEqualsSigned
}

impl AsRef<Comparison> for Comparison {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'c> From<&'c Comparison> for u8 {
    fn from(comparison: &'c Comparison) -> u8 {
        match *comparison {
            Comparison::Absolute => 0x00,
            Comparison::Equals => 0x10,
            Comparison::Greater => 0x20,
            Comparison::GreaterEquals => 0x30,
            Comparison::BitAnd => 0x40,
            Comparison::NotEquals => 0x50,
            Comparison::GreaterSigned => 0x60,
            Comparison::GreaterEqualsSigned => 0x70
        }
    }
}

pub struct FunctionCall {
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl FunctionCall {
    pub fn new() -> Self {
        FunctionCall {
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for FunctionCall {
    fn opt_code_byte(&self) -> u8 {
        0x85
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
        self
    }
}

pub struct Exit {
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32
}

impl Exit {
    pub fn new() -> Self {
        Exit {
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            imm: 0x00_00_00_00
        }
    }
}

impl Instruction for Exit {
    fn opt_code_byte(&self) -> u8 {
        0x95
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
    }

    fn offset(&self) -> u16 {
        self.offset
    }

    fn imm(&self) -> u32 {
        self.imm
    }

    fn dst_reg(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    fn src_reg(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    fn offset_bytes(mut self, offset: u16) -> Self {
        self.offset = offset;
        self
    }

    fn immediate(mut self, imm: u32) -> Self {
        self.imm = imm;
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
            program.add(FunctionCall::new().immediate(0x11_22_33_44));

            assert_eq!(program.as_bytes(), &[0x85, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn exit_operation() {
            let mut program = BpfCode::new();
            program.add(Exit::new());

            assert_eq!(program.as_bytes(), &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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
                program.add(Jump::new(Comparison::Equals, Source::Register).dst_reg(0x01).src_reg(0x02));

                assert_eq!(program.as_bytes(), &[0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::Greater, Source::Register).dst_reg(0x03).src_reg(0x02));

                assert_eq!(program.as_bytes(), &[0x2d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_src() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterEquals, Source::Register).dst_reg(0x04).src_reg(0x01));

                assert_eq!(program.as_bytes(), &[0x3d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_src_not_equal_zero() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::BitAnd, Source::Register).dst_reg(0x05).src_reg(0x02));

                assert_eq!(program.as_bytes(), &[0x4d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_src() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::NotEquals, Source::Register).dst_reg(0x03).src_reg(0x05));

                assert_eq!(program.as_bytes(), &[0x5d, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_src_signed() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterSigned, Source::Register).dst_reg(0x04).src_reg(0x01));

                assert_eq!(program.as_bytes(), &[0x6d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterEqualsSigned, Source::Register).dst_reg(0x01).src_reg(0x03));

                assert_eq!(program.as_bytes(), &[0x7d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn jump_to_label() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::Absolute, Source::Immediate).offset_bytes(0x00_11));

                assert_eq!(program.as_bytes(), &[0x05, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_equals_const() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::Equals, Source::Immediate).dst_reg(0x01).immediate(0x00_11_22_33));

                assert_eq!(program.as_bytes(), &[0x15, 0x01, 0x00, 0x00, 0x33, 0x22, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::Greater, Source::Immediate).dst_reg(0x02).immediate(0x00_11_00_11));

                assert_eq!(program.as_bytes(), &[0x25, 0x02, 0x00, 0x00, 0x11, 0x00, 0x11, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_to_const() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterEquals, Source::Immediate).dst_reg(0x04).immediate(0x00_22_11_00));

                assert_eq!(program.as_bytes(), &[0x35, 0x04, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00]);
            }

            #[test]
            fn jump_on_dst_bit_and_with_const_not_equal_zero() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::BitAnd, Source::Immediate).dst_reg(0x05));

                assert_eq!(program.as_bytes(), &[0x45, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_not_equals_const() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::NotEquals, Source::Immediate).dst_reg(0x03));

                assert_eq!(program.as_bytes(), &[0x55, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_than_const_signed() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterSigned, Source::Immediate).dst_reg(0x04));

                assert_eq!(program.as_bytes(), &[0x65, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn jump_on_dst_greater_or_equals_src_signed() {
                let mut program = BpfCode::new();
                program.add(Jump::new(Comparison::GreaterEqualsSigned, Source::Immediate).dst_reg(0x01));

                assert_eq!(program.as_bytes(), &[0x75, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }
    }

    #[cfg(test)]
    mod store_instructions {
        use super::super::*;

        #[test]
        fn store_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::Word, AddressSource::Immediate).dst_reg(0x01).offset_bytes(0x00_11).immediate(0x11_22_33_44));

            assert_eq!(program.as_bytes(), &[0x62, 0x01, 0x11, 0x00, 0x44, 0x33, 0x22, 0x11]);
        }

        #[test]
        fn store_half_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::HalfWord, AddressSource::Immediate).dst_reg(0x02).offset_bytes(0x11_22));

            assert_eq!(program.as_bytes(), &[0x6a, 0x02, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::Byte, AddressSource::Immediate));

            assert_eq!(program.as_bytes(), &[0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_immediate_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::DoubleWord, AddressSource::Immediate));

            assert_eq!(program.as_bytes(), &[0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::Word, AddressSource::Register).dst_reg(0x01).src_reg(0x02));

            assert_eq!(program.as_bytes(), &[0x63, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_half_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::HalfWord, AddressSource::Register));

            assert_eq!(program.as_bytes(), &[0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_byte_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::Byte, AddressSource::Register));

            assert_eq!(program.as_bytes(), &[0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn store_double_word_from_dst_into_src_address() {
            let mut program = BpfCode::new();
            program.add(Store::new(MemSize::DoubleWord, AddressSource::Register));

            assert_eq!(program.as_bytes(), &[0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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
                program.add(Load::new(MemSize::Word, Addressing::Undef, AddressSource::Register).dst_reg(0x01).src_reg(0x02).offset_bytes(0x00_02));

                assert_eq!(program.as_bytes(), &[0x61, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_half_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::HalfWord, Addressing::Undef, AddressSource::Register).dst_reg(0x02).src_reg(0x01).offset_bytes(0x11_22));

                assert_eq!(program.as_bytes(), &[0x69, 0x12, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_byte_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::Byte, Addressing::Undef, AddressSource::Register).dst_reg(0x01).src_reg(0x04).offset_bytes(0x00_11));

                assert_eq!(program.as_bytes(), &[0x71, 0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_double_word_from_src_reg_with_offset() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::DoubleWord, Addressing::Undef, AddressSource::Register).dst_reg(0x04).src_reg(0x05).offset_bytes(0x44_55));

                assert_eq!(program.as_bytes(), &[0x79, 0x54, 0x55, 0x44, 0x00, 0x00, 0x00, 0x00]);
            }
        }

        #[cfg(test)]
        mod immediate {
            use super::super::super::*;

            #[test]
            fn load_double_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::DoubleWord, Addressing::Undef, AddressSource::Immediate).dst_reg(0x01).immediate(0x00_01_02_03));

                assert_eq!(program.as_bytes(), &[0x18, 0x01, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
            }

            #[test]
            fn load_abs_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::Word, Addressing::Abs, AddressSource::Immediate));

                assert_eq!(program.as_bytes(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_half_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::HalfWord, Addressing::Abs, AddressSource::Immediate).dst_reg(0x05));

                assert_eq!(program.as_bytes(), &[0x28, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_byte() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::Byte, Addressing::Abs, AddressSource::Immediate).dst_reg(0x01));

                assert_eq!(program.as_bytes(), &[0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_abs_double_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::DoubleWord, Addressing::Abs, AddressSource::Immediate).dst_reg(0x01).immediate(0x01_02_03_04));

                assert_eq!(program.as_bytes(), &[0x38, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
            }

            #[test]
            fn load_indirect_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::Word, Addressing::Ind, AddressSource::Immediate));

                assert_eq!(program.as_bytes(), &[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_half_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::HalfWord, Addressing::Ind, AddressSource::Immediate));

                assert_eq!(program.as_bytes(), &[0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_byte() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::Byte, Addressing::Ind, AddressSource::Immediate));

                assert_eq!(program.as_bytes(), &[0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }

            #[test]
            fn load_indirect_double_word() {
                let mut program = BpfCode::new();
                program.add(Load::new(MemSize::DoubleWord, Addressing::Ind, AddressSource::Immediate));

                assert_eq!(program.as_bytes(), &[0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
        }
    }

    #[cfg(test)]
    mod byte_swap_instructions {
        use super::super::*;

        #[test]
        fn convert_host_to_little_endian_16bits() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Little).dst_reg(0x01).immediate(0x00_00_00_10));

            assert_eq!(program.as_bytes(), &[0xd4, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_32bits() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Little).dst_reg(0x02).immediate(0x00_00_00_20));

            assert_eq!(program.as_bytes(), &[0xd4, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_little_endian_64bit() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Little).dst_reg(0x03).immediate(0x00_00_00_40));

            assert_eq!(program.as_bytes(), &[0xd4, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_16bits() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Big).dst_reg(0x01).immediate(0x00_00_00_10));

            assert_eq!(program.as_bytes(), &[0xdc, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_32bits() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Big).dst_reg(0x02).immediate(0x00_00_00_20));

            assert_eq!(program.as_bytes(), &[0xdc, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn convert_host_to_big_endian_64bit() {
            let mut program = BpfCode::new();
            program.add(SwapBytes::new(Endian::Big).dst_reg(0x03).immediate(0x00_00_00_40));

            assert_eq!(program.as_bytes(), &[0xdc, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
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
                    program.add(Move::new(Source::Immediate, Op::Add, Arch::X64).dst_reg(0x02).immediate(0x01_02_03_04));

                    assert_eq!(program.as_bytes(), &[0x07, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Sub, Arch::X64).dst_reg(0x04).immediate(0x00_01_02_03));

                    assert_eq!(program.as_bytes(), &[0x17, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Mul, Arch::X64).dst_reg(0x05).immediate(0x04_03_02_01));

                    assert_eq!(program.as_bytes(), &[0x27, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Div, Arch::X64).dst_reg(0x02).immediate(0x00_ff_00_ff));

                    assert_eq!(program.as_bytes(), &[0x37, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitOr, Arch::X64).dst_reg(0x02).immediate(0x00_11_00_22));

                    assert_eq!(program.as_bytes(), &[0x47, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitAnd, Arch::X64).dst_reg(0x02).immediate(0x11_22_33_44));

                    assert_eq!(program.as_bytes(), &[0x57, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::LShift, Arch::X64).dst_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x67, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::LogicalRShift, Arch::X64).dst_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x77, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Negate, Arch::X64).dst_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Mod, Arch::X64).dst_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x97, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitXor, Arch::X64).dst_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0xa7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::NoOp, Arch::X64).dst_reg(0x01).immediate(0x00_00_00_FF));

                    assert_eq!(program.as_bytes(), &[0xb7, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::SignRShift, Arch::X64).dst_reg(0x05));

                    assert_eq!(program.as_bytes(), &[0xc7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Add, Arch::X64).dst_reg(0x03).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x0f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Sub, Arch::X64).dst_reg(0x03).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0x1f, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Mul, Arch::X64).dst_reg(0x04).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0x2f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Div, Arch::X64).dst_reg(0x01).src_reg(0x00));

                    assert_eq!(program.as_bytes(), &[0x3f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitOr, Arch::X64).dst_reg(0x03).src_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x4f, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitAnd, Arch::X64).dst_reg(0x03).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x5f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::LShift, Arch::X64).dst_reg(0x02).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0x6f, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::LogicalRShift, Arch::X64).dst_reg(0x02).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0x7f, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Mod, Arch::X64).dst_reg(0x01).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x9f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::NoOp, Arch::X64).dst_reg(0x00).src_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitXor, Arch::X64).dst_reg(0x02).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0xaf, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::SignRShift, Arch::X64).dst_reg(0x02).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0xcf, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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
                    program.add(Move::new(Source::Immediate, Op::Add, Arch::X32).dst_reg(0x02).immediate(0x01_02_03_04));

                    assert_eq!(program.as_bytes(), &[0x04, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);
                }

                #[test]
                fn move_sub_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Sub, Arch::X32).dst_reg(0x04).immediate(0x00_01_02_03));

                    assert_eq!(program.as_bytes(), &[0x14, 0x04, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00]);
                }

                #[test]
                fn move_mul_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Mul, Arch::X32).dst_reg(0x05).immediate(0x04_03_02_01));

                    assert_eq!(program.as_bytes(), &[0x24, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
                }

                #[test]
                fn move_div_constant_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Div, Arch::X32).dst_reg(0x02).immediate(0x00_ff_00_ff));

                    assert_eq!(program.as_bytes(), &[0x34, 0x02, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
                }

                #[test]
                fn move_bit_or_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitOr, Arch::X32).dst_reg(0x02).immediate(0x00_11_00_22));

                    assert_eq!(program.as_bytes(), &[0x44, 0x02, 0x00, 0x00, 0x22, 0x00, 0x11, 0x00]);
                }

                #[test]
                fn move_bit_and_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitAnd, Arch::X32).dst_reg(0x02).immediate(0x11_22_33_44));

                    assert_eq!(program.as_bytes(), &[0x54, 0x02, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]);
                }

                #[test]
                fn move_left_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::LShift, Arch::X32).dst_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::LogicalRShift, Arch::X32).dst_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_negate_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Negate, Arch::X32).dst_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x84, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::Mod, Arch::X32).dst_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x94, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::BitXor, Arch::X32).dst_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0xa4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::NoOp, Arch::X32).dst_reg(0x01).immediate(0x00_00_00_FF));

                    assert_eq!(program.as_bytes(), &[0xb4, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_const_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Immediate, Op::SignRShift, Arch::X32).dst_reg(0x05));

                    assert_eq!(program.as_bytes(), &[0xc4, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }

            #[cfg(test)]
            mod register {
                use super::super::super::super::*;

                #[test]
                fn move_and_add_from_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Add, Arch::X32).dst_reg(0x03).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x0c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_sub_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Sub, Arch::X32).dst_reg(0x03).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0x1c, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mul_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Mul, Arch::X32).dst_reg(0x04).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0x2c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_div_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Div, Arch::X32).dst_reg(0x01).src_reg(0x00));

                    assert_eq!(program.as_bytes(), &[0x3c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_or_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitOr, Arch::X32).dst_reg(0x03).src_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0x4c, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_and_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitAnd, Arch::X32).dst_reg(0x03).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x5c, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_left_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::LShift, Arch::X32).dst_reg(0x02).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0x6c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_logical_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::LogicalRShift, Arch::X32).dst_reg(0x02).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0x7c, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_mod_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::Mod, Arch::X32).dst_reg(0x01).src_reg(0x02));

                    assert_eq!(program.as_bytes(), &[0x9c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_bit_xor_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::BitXor, Arch::X32).dst_reg(0x02).src_reg(0x04));

                    assert_eq!(program.as_bytes(), &[0xac, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_from_register_to_another_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::NoOp, Arch::X32).dst_reg(0x00).src_reg(0x01));

                    assert_eq!(program.as_bytes(), &[0xbc, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                #[test]
                fn move_signed_right_shift_from_register_to_register() {
                    let mut program = BpfCode::new();
                    program.add(Move::new(Source::Register, Op::SignRShift, Arch::X32).dst_reg(0x02).src_reg(0x03));

                    assert_eq!(program.as_bytes(), &[0xcc, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }
            }
        }
    }
}
