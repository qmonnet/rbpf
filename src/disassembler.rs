// Copyright 2017 Quentin Monnet <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! Functions in this module are used to handle eBPF programs with a higher level representation,
//! for example to disassemble the code into a human-readable format.

use ebpf;

#[inline]
fn alu_imm_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, {:#x}", name, insn.dst, insn.imm)
}

#[inline]
fn alu_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, r{}", name, insn.dst, insn.src)
}

#[inline]
fn byteswap_str(name: &str, insn: &ebpf::Insn) -> String {
    match insn.off {
        16 | 32 | 64 => {},
        _ => println!("[Disassembler] Warning: Invalid offset value for {} insn", name)
    }
    format!("{}{} r{}", name, insn.off, insn.dst)
}

#[inline]
fn ld_st_imm_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} [r{}+{:#x}], {:#x}", name, insn.dst, insn.off, insn.imm)
}

#[inline]
fn ld_st_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} [r{}+{:#x}], r{}", name, insn.dst, insn.off, insn.src)
}

#[inline]
fn ldabs_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} {:#x}", name, insn.imm)
}

#[inline]
fn ldind_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, {:#x}", name, insn.src, insn.imm)
}

#[inline]
fn jmp_imm_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, {:#x}, {:+#x}", name, insn.dst, insn.imm, insn.off)
}

#[inline]
fn jmp_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, r{}, {:+#x}", name, insn.dst, insn.src, insn.off)
}

/// High-level representation of an eBPF instruction.
///
/// In addition to standard operation code and various operand, this struct has the following
/// properties:
///
/// * It stores a name, corresponding to a mnemonic for the operation code.
/// * It also stores a description, which is a mnemonic for the full instruction, using the actual
///   values of the relevant operands, and that can be used for disassembling the eBPF program for
///   example.
/// * Immediate values are stored in an `i64` instead of a traditional i32, in order to merge the
///   two parts of (otherwise double-length) `LD_DW_IMM` instructions.
///
/// See <https://www.kernel.org/doc/Documentation/networking/filter.txt> for the Linux kernel
/// documentation about eBPF, or <https://github.com/iovisor/bpf-docs/blob/master/eBPF.md> for a
/// more concise version.
#[derive(Debug, PartialEq)]
pub struct HLInsn {
    /// Operation code.
    pub opc:  u8,
    /// Name (mnemonic). This name is not canon.
    pub name: String,
    /// Description of the instruction. This is not canon.
    pub desc: String,
    /// Destination register operand.
    pub dst:  u8,
    /// Source register operand.
    pub src:  u8,
    /// Offset operand.
    pub off:  i16,
    /// Immediate value operand. For `LD_DW_IMM` instructions, contains the whole value merged from
    /// the two 8-bytes parts of the instruction.
    pub imm:  i64,
}

/// Return a vector of `struct HLInsn` built from an eBPF program.
///
/// This is made public to provide a way to manipulate a program as a vector of instructions, in a
/// high-level format, for example for dumping the program instruction after instruction with a
/// custom format.
///
/// Note that the two parts of `LD_DW_IMM` instructions (that have the size of two standard
/// instructions) are considered as making a single immediate value. As a consequence, the number
/// of instructions stored in the vector may not be equal to the size in bytes of the program
/// divided by the length of an instructions.
///
/// To do so, the immediate value operand is stored as an `i64` instead as an i32, so be careful
/// when you use it (see example `examples/to_json.rs`).
///
/// This is to oppose to `ebpf::to_insn_vec()` function, that treats instructions on a low-level
/// ground and do not merge the parts of `LD_DW_IMM`. Also, the version in `ebpf` module does not
/// use names or descriptions when storing the instructions.
///
/// # Examples
///
/// ```
/// use rbpf::disassembler;
///
/// let prog = vec![
///     0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55,
///     0x00, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11,
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let v = disassembler::to_insn_vec(&prog);
/// disassembler::disassemble(&prog);
/// assert_eq!(v, vec![
///     disassembler::HLInsn {
///         opc: 0x18,
///         name: "lddw".to_string(),
///         desc: "lddw r0, 0x1122334455667788".to_string(),
///         dst: 0,
///         src: 0,
///         off: 0,
///         imm: 0x1122334455667788
///     },
///     disassembler::HLInsn {
///         opc: 0x95,
///         name: "exit".to_string(),
///         desc: "exit".to_string(),
///         dst: 0,
///         src: 0,
///         off: 0,
///         imm: 0
///     },
/// ]);
/// ```
pub fn to_insn_vec(prog: &[u8]) -> Vec<HLInsn> {
    if prog.len() % ebpf::INSN_SIZE != 0 {
        panic!("[Disassembler] Error: eBPF program length must be a multiple of {:?} octets",
               ebpf::INSN_SIZE);
    }
    if prog.len() == 0 {
        return vec![];
    }

    let mut res = vec![];
    let mut insn_ptr:usize = 0;

    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        let insn = ebpf::get_insn(prog, insn_ptr);

        let name;
        let desc;
        let mut imm = insn.imm as i64;
        match insn.opc {

            // BPF_LD class
            ebpf::LD_ABS_B   => { name = "ldabsb";  desc = ldabs_str(name, &insn); },
            ebpf::LD_ABS_H   => { name = "ldabsh";  desc = ldabs_str(name, &insn); },
            ebpf::LD_ABS_W   => { name = "ldabsw";  desc = ldabs_str(name, &insn); },
            ebpf::LD_ABS_DW  => { name = "ldabsdw"; desc = ldabs_str(name, &insn); },
            ebpf::LD_IND_B   => { name = "ldindb";  desc = ldind_str(name, &insn); },
            ebpf::LD_IND_H   => { name = "ldindh";  desc = ldind_str(name, &insn); },
            ebpf::LD_IND_W   => { name = "ldindw";  desc = ldind_str(name, &insn); },
            ebpf::LD_IND_DW  => { name = "ldinddw"; desc = ldind_str(name, &insn); },

            // BPF_LDX class
            ebpf::LD_DW_IMM  => {
                insn_ptr += 1;
                let next_insn = ebpf::get_insn(prog, insn_ptr);
                imm = ((insn.imm as u32) as u64 + ((next_insn.imm as u64) << 32)) as i64;
                name = "lddw"; desc = format!("{} r{:}, {:#x}", name, insn.dst, imm);
            },
            ebpf::LD_B_REG   => { name = "ldxb";  desc = ld_st_reg_str(name, &insn); },
            ebpf::LD_H_REG   => { name = "ldxh";  desc = ld_st_reg_str(name, &insn); },
            ebpf::LD_W_REG   => { name = "ldxw";  desc = ld_st_reg_str(name, &insn); },
            ebpf::LD_DW_REG  => { name = "ldxdw"; desc = ld_st_reg_str(name, &insn); },

            // BPF_ST class
            ebpf::ST_B_IMM   => { name = "stb";  desc = ld_st_imm_str(name, &insn); },
            ebpf::ST_H_IMM   => { name = "sth";  desc = ld_st_imm_str(name, &insn); },
            ebpf::ST_W_IMM   => { name = "stw";  desc = ld_st_imm_str(name, &insn); },
            ebpf::ST_DW_IMM  => { name = "stdw"; desc = ld_st_imm_str(name, &insn); },

            // BPF_STX class
            ebpf::ST_B_REG   => { name = "stxb";      desc = ld_st_reg_str(name, &insn); },
            ebpf::ST_H_REG   => { name = "stxh";      desc = ld_st_reg_str(name, &insn); },
            ebpf::ST_W_REG   => { name = "stxw";      desc = ld_st_reg_str(name, &insn); },
            ebpf::ST_DW_REG  => { name = "stxdw";     desc = ld_st_reg_str(name, &insn); },
            ebpf::ST_W_XADD  => { name = "stxxaddw";  desc = ld_st_reg_str(name, &insn); },
            ebpf::ST_DW_XADD => { name = "stxxadddw"; desc = ld_st_reg_str(name, &insn); },

            // BPF_ALU class
            ebpf::ADD32_IMM  => { name = "add32";  desc = alu_imm_str(name, &insn);  },
            ebpf::ADD32_REG  => { name = "add32";  desc = alu_reg_str(name, &insn);  },
            ebpf::SUB32_IMM  => { name = "sub32";  desc = alu_imm_str(name, &insn);  },
            ebpf::SUB32_REG  => { name = "sub32";  desc = alu_reg_str(name, &insn);  },
            ebpf::MUL32_IMM  => { name = "mul32";  desc = alu_imm_str(name, &insn);  },
            ebpf::MUL32_REG  => { name = "mul32";  desc = alu_reg_str(name, &insn);  },
            ebpf::DIV32_IMM  => { name = "div32";  desc = alu_imm_str(name, &insn);  },
            ebpf::DIV32_REG  => { name = "div32";  desc = alu_reg_str(name, &insn);  },
            ebpf::OR32_IMM   => { name = "or32";   desc = alu_imm_str(name, &insn);  },
            ebpf::OR32_REG   => { name = "or32";   desc = alu_reg_str(name, &insn);  },
            ebpf::AND32_IMM  => { name = "and32";  desc = alu_imm_str(name, &insn);  },
            ebpf::AND32_REG  => { name = "and32";  desc = alu_reg_str(name, &insn);  },
            ebpf::LSH32_IMM  => { name = "lsh32";  desc = alu_imm_str(name, &insn);  },
            ebpf::LSH32_REG  => { name = "lsh32";  desc = alu_reg_str(name, &insn);  },
            ebpf::RSH32_IMM  => { name = "rsh32";  desc = alu_imm_str(name, &insn);  },
            ebpf::RSH32_REG  => { name = "rsh32";  desc = alu_reg_str(name, &insn);  },
            ebpf::NEG32      => { name = "neg32";  desc = format!("{} r{:}", name, insn.dst); },
            ebpf::MOD32_IMM  => { name = "mod32";  desc = alu_imm_str(name, &insn);  },
            ebpf::MOD32_REG  => { name = "mod32";  desc = alu_reg_str(name, &insn);  },
            ebpf::XOR32_IMM  => { name = "xor32";  desc = alu_imm_str(name, &insn);  },
            ebpf::XOR32_REG  => { name = "xor32";  desc = alu_reg_str(name, &insn);  },
            ebpf::MOV32_IMM  => { name = "mov32";  desc = alu_imm_str(name, &insn);  },
            ebpf::MOV32_REG  => { name = "mov32";  desc = alu_reg_str(name, &insn);  },
            ebpf::ARSH32_IMM => { name = "arsh32"; desc = alu_imm_str(name, &insn);  },
            ebpf::ARSH32_REG => { name = "arsh32"; desc = alu_reg_str(name, &insn);  },
            ebpf::LE         => { name = "le";     desc = byteswap_str(name, &insn); },
            ebpf::BE         => { name = "be";     desc = byteswap_str(name, &insn); },

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => { name = "add64";  desc = alu_imm_str(name, &insn); },
            ebpf::ADD64_REG  => { name = "add64";  desc = alu_reg_str(name, &insn); },
            ebpf::SUB64_IMM  => { name = "sub64";  desc = alu_imm_str(name, &insn); },
            ebpf::SUB64_REG  => { name = "sub64";  desc = alu_reg_str(name, &insn); },
            ebpf::MUL64_IMM  => { name = "mul64";  desc = alu_imm_str(name, &insn); },
            ebpf::MUL64_REG  => { name = "mul64";  desc = alu_reg_str(name, &insn); },
            ebpf::DIV64_IMM  => { name = "div64";  desc = alu_imm_str(name, &insn); },
            ebpf::DIV64_REG  => { name = "div64";  desc = alu_reg_str(name, &insn); },
            ebpf::OR64_IMM   => { name = "or64";   desc = alu_imm_str(name, &insn); },
            ebpf::OR64_REG   => { name = "or64";   desc = alu_reg_str(name, &insn); },
            ebpf::AND64_IMM  => { name = "and64";  desc = alu_imm_str(name, &insn); },
            ebpf::AND64_REG  => { name = "and64";  desc = alu_reg_str(name, &insn); },
            ebpf::LSH64_IMM  => { name = "lsh64";  desc = alu_imm_str(name, &insn); },
            ebpf::LSH64_REG  => { name = "lsh64";  desc = alu_reg_str(name, &insn); },
            ebpf::RSH64_IMM  => { name = "rsh64";  desc = alu_imm_str(name, &insn); },
            ebpf::RSH64_REG  => { name = "rsh64";  desc = alu_reg_str(name, &insn); },
            ebpf::NEG64      => { name = "neg64";  desc = format!("{} r{:}", name, insn.dst); },
            ebpf::MOD64_IMM  => { name = "mod64";  desc = alu_imm_str(name, &insn); },
            ebpf::MOD64_REG  => { name = "mod64";  desc = alu_reg_str(name, &insn); },
            ebpf::XOR64_IMM  => { name = "xor64";  desc = alu_imm_str(name, &insn); },
            ebpf::XOR64_REG  => { name = "xor64";  desc = alu_reg_str(name, &insn); },
            ebpf::MOV64_IMM  => { name = "mov64";  desc = alu_imm_str(name, &insn); },
            ebpf::MOV64_REG  => { name = "mov64";  desc = alu_reg_str(name, &insn); },
            ebpf::ARSH64_IMM => { name = "arsh64"; desc = alu_imm_str(name, &insn); },
            ebpf::ARSH64_REG => { name = "arsh64"; desc = alu_reg_str(name, &insn); },

            // BPF_JMP class
            ebpf::JA         => { name = "ja";   desc = format!("{} {:+#x}", name, insn.off); },
            ebpf::JEQ_IMM    => { name = "jeq";  desc = jmp_imm_str(name, &insn); },
            ebpf::JEQ_REG    => { name = "jeq";  desc = jmp_reg_str(name, &insn); },
            ebpf::JGT_IMM    => { name = "jgt";  desc = jmp_imm_str(name, &insn); },
            ebpf::JGT_REG    => { name = "jgt";  desc = jmp_reg_str(name, &insn); },
            ebpf::JGE_IMM    => { name = "jge";  desc = jmp_imm_str(name, &insn); },
            ebpf::JGE_REG    => { name = "jge";  desc = jmp_reg_str(name, &insn); },
            ebpf::JSET_IMM   => { name = "jset"; desc = jmp_imm_str(name, &insn); },
            ebpf::JSET_REG   => { name = "jset"; desc = jmp_reg_str(name, &insn); },
            ebpf::JNE_IMM    => { name = "jne";  desc = jmp_imm_str(name, &insn); },
            ebpf::JNE_REG    => { name = "jne";  desc = jmp_reg_str(name, &insn); },
            ebpf::JSGT_IMM   => { name = "jsgt"; desc = jmp_imm_str(name, &insn); },
            ebpf::JSGT_REG   => { name = "jsgt"; desc = jmp_reg_str(name, &insn); },
            ebpf::JSGE_IMM   => { name = "jsge"; desc = jmp_imm_str(name, &insn); },
            ebpf::JSGE_REG   => { name = "jsge"; desc = jmp_reg_str(name, &insn); },
            ebpf::CALL       => { name = "call"; desc = format!("{} {:#x}", name, insn.imm); },
            ebpf::TAIL_CALL  => { name = "tail_call"; desc = name.to_string(); },
            ebpf::EXIT       => { name = "exit";      desc = name.to_string(); },

            _                => {
                panic!("[Disassembler] Error: unknown eBPF opcode {:#2x} (insn #{:?})",
                       insn.opc, insn_ptr);
            },
        };

        let hl_insn = HLInsn {
            opc:  insn.opc,
            name: name.to_string(),
            desc: desc,
            dst:  insn.dst,
            src:  insn.src,
            off:  insn.off,
            imm:  imm,
        };

        res.push(hl_insn);

        insn_ptr += 1;
    };
    res
}

/// Disassemble an eBPF program into human-readable instructions and prints it to standard output.
///
/// The program is not checked for errors or inconsistencies.
///
/// # Examples
///
/// ```
/// use rbpf::disassembler;
/// let prog = vec![
///     0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
///     0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
///     0xbf, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0xdc, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x87, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
/// disassembler::disassemble(&prog);
/// ```
///
/// This will produce the following output:
///
/// ```test
/// add64 r1, 0x605
/// mov64 r2, 0x32
/// mov64 r1, r0
/// be16 r0
/// neg64 r8
/// exit
/// ```
pub fn disassemble(prog: &[u8]) {
    if prog.len() % ebpf::INSN_SIZE != 0 {
        panic!("[Disassembler] Error: eBPF program length must be a multiple of {:?} octets",
               ebpf::INSN_SIZE);
    }
    if prog.len() == 0 {
        return;
    }

    let insns = to_insn_vec(prog);

    for insn in insns {
        println!("{}", insn.desc);
    }
}
