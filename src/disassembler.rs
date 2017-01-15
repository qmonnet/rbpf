// Copyright 2017 Quentin Monnet <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! Disassemble eBPF code into human-readable instructions.

use ebpf;
use std;

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

pub struct HLInsn {
    pub opc:  u8,
    pub name: String,
    pub desc: String,
    pub dst:  u8,
    pub src:  u8,
    pub off:  i16,
    pub imm:  i64,
}

pub fn to_insn_vec(prog: &std::vec::Vec<u8>) -> std::vec::Vec<HLInsn> {
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

        if insn.opc == ebpf::LD_DW_IMM {
            insn_ptr += 1;
            let next_insn = ebpf::get_insn(prog, insn_ptr);
            imm = ((insn.imm as u32) as u64 + ((next_insn.imm as u64) << 32)) as i64;
        }
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
/// panic!();
/// ```
pub fn disassemble(prog: &std::vec::Vec<u8>) {
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
