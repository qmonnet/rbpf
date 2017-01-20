pub enum MemSize {
    Double,
    Half
}

pub struct ProgramCodeBuilder {
    instructions: Vec<u8>
}

impl <'p> ProgramCodeBuilder {

    pub fn new() -> Self {
        ProgramCodeBuilder { instructions: vec![] }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.instructions.as_slice()
    }

    pub fn bind_value(&'p mut self) -> Operation<'p> {
        Operation::new(self, 0xb7)
    }

    pub fn bind_register(&'p mut self) -> Operation<'p> {
        Operation::new(self, 0xbf)
    }

    pub fn load_mem(&'p mut self, size: MemSize) -> Operation<'p> {
        let opcode = match size {
            MemSize::Double => 0x79,
            MemSize::Half => 0x69
        };
        Operation::new(self, opcode)
    }

    pub fn exit(&'p mut self) -> Operation<'p> {
        Operation::new(self, 0x95)
    }
}

pub struct Operation<'p> {
    program: &'p mut ProgramCodeBuilder,
    op: u8,
    dst: u8,
    src: u8,
    offset: u16,
    immediate: u32
}

impl <'p> Operation<'p> {

    fn new(program: &'p mut ProgramCodeBuilder, op: u8) -> Operation<'p> {
        Operation {
            program: program,
            op: op,
            dst: 0x00,
            src: 0x00,
            offset: 0x00_00,
            immediate: 0x00_00_00_00
        }
    }

    pub fn dst(&'p mut self, dst_register: u8) -> &'p mut Operation<'p> {
        self.dst = dst_register;
        self
    }

    pub fn src(&'p mut self, src_register: u8) -> &'p mut Operation<'p> {
        self.src = src_register;
        self
    }

    pub fn offset(&'p mut self, offset: u16) -> &'p mut Operation<'p> {
        self.offset = offset;
        self
    }

    pub fn value(&'p mut self, immediate: u32) -> &'p mut Operation<'p> {
        self.immediate = immediate;
        self
    }

    pub fn push(&'p mut self) -> &'p mut ProgramCodeBuilder {
        {
            let mut ins: &mut Vec<u8> = self.program.instructions.as_mut();
            ins.push(self.op);
            ins.push((self.src << 4) | self.dst);
            ins.push((self.offset & 0x00_FF) as u8);
            ins.push(((self.offset & 0xFF_00) >> 8) as u8);
            ins.push((self.immediate & 0x00_00_00_FF) as u8);
            ins.push(((self.immediate & 0x00_00_FF_00) >> 8) as u8);
            ins.push(((self.immediate & 0x00_FF_00_00) >> 16) as u8);
            ins.push(((self.immediate & 0xFF_00_00_00) >> 24) as u8);
        }
        self.program
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_program_code() {
        let program = ProgramCodeBuilder::new();

        assert_eq!(program.as_bytes(), &[]);
    }

    #[test]
    fn assign_zero_to_r0() {
        let mut program = ProgramCodeBuilder::new();

        program.bind_value().dst(0x00).value(0x00_00_00_00).push();

        assert_eq!(program.as_bytes(), &[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn assign_r1_to_r0() {
        let mut program = ProgramCodeBuilder::new();

        program
            .bind_value().dst(0x01).value(0x00_00_00_0F).push()
            .bind_register().dst(0x00).src(0x01).push();

        assert_eq!(
            program.as_bytes(),
            &[
                0xb7, 0x01, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00,
                0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn load_doubled_word_from_memory_address_r3_to_r2() {
        let mut builder = ProgramCodeBuilder::new();

        builder.load_mem(MemSize::Double).dst(0x02).src(0x03).push();

        assert_eq!(builder.as_bytes(), &[0x79, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn load_half_a_word_from_memory_address_r4_to_r0() {
        let mut builder = ProgramCodeBuilder::new();

        builder.load_mem(MemSize::Half).dst(0x00).src(0x04).offset(0x00_02).push();

        assert_eq!(builder.as_bytes(), &[0x69, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn exit_program_op() {
        let mut builder = ProgramCodeBuilder::new();

        builder.exit().push();

        assert_eq!(builder.as_bytes(), &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}
