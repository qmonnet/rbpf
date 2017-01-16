// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: safety checks, originally in C)
// Copyright 2016 Quentin Monnet <quentin.monnet@6wind.com>
//      (Translation to Rust)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


// This “verifier” performs simple checks when the eBPF program is loaded into the VM (before it is
// interpreted or JIT-compiled). It has nothing to do with the much more elaborated verifier inside
// Linux kernel. There is no verification regarding the program flow control (should be a Direct
// Acyclic Graph) or the consistency for registers usage (the verifier of the kernel assigns types
// to the registers and is much stricter).
//
// On the other hand, rbpf is not expected to run in kernel space.
//
// Improving the verifier would be nice, but this is not trivial (and Linux kernel is under GPL
// license, so we cannot copy it).
//
// Contrary to the verifier of the Linux kernel, this one does not modify the bytecode at all.


use ebpf;

fn check_prog_len(prog: &[u8]) {
    if prog.len() % ebpf::INSN_SIZE != 0 {
        panic!("[Verifier] Error: eBPF program length must be a multiple of {:?} octets",
               ebpf::INSN_SIZE);
    }
    if prog.len() > ebpf::PROG_MAX_SIZE {
        panic!("[Verifier] Error: eBPF program length limited to {:?}, here {:?}",
               ebpf::PROG_MAX_INSNS, prog.len() / ebpf::INSN_SIZE);
    }

    if prog.len() == 0 {
        panic!("[Verifier] Error: program does not end with “EXIT” instruction");
    }
    let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    if last_insn.opc != ebpf::EXIT {
        panic!("[Verifier] Error: program does not end with “EXIT” instruction");
    }
}

fn check_imm_nonzero(insn: &ebpf::Insn, insn_ptr: usize) {
    if insn.imm == 0 {
        panic!("[Verifier] Error: division by 0 (insn #{:?})", insn_ptr);
    }
}

fn check_imm_endian(insn: &ebpf::Insn, insn_ptr: usize) {
    match insn.imm {
        16 | 32 | 64 => return,
        _ => panic!("[Verifier] Error: unsupported argument for LE/BE (insn #{:?})", insn_ptr)
    }
}

fn check_load_dw(prog: &[u8], insn_ptr: usize) {
    // We know we can reach next insn since we enforce an EXIT insn at the end of program, while
    // this function should be called only for LD_DW insn, that cannot be last in program.
    let next_insn = ebpf::get_insn(prog, insn_ptr + 1);
    if next_insn.opc != 0 {
        panic!("[Verifier] Error: incomplete LD_DW instruction (insn #{:?})", insn_ptr);
    }

}

fn check_jmp_offset(prog: &[u8], insn_ptr: usize) {
    let insn = ebpf::get_insn(prog, insn_ptr);
    if insn.off == -1 {
        panic!("[Verifier] Error: infinite loop (insn #{:?})", insn_ptr);
    }

    let dst_insn_ptr = insn_ptr as isize + 1 + insn.off as isize;
    if dst_insn_ptr < 0 || dst_insn_ptr as usize >= (prog.len() / ebpf::INSN_SIZE) {
        panic!("[Verifier] Error: jump out of code to #{:?} (insn #{:?})",
               dst_insn_ptr, insn_ptr);
    }

    let dst_insn = ebpf::get_insn(prog, dst_insn_ptr as usize);
    if dst_insn.opc == 0 {
        panic!("[Verifier] Error: jump to middle of LD_DW at #{:?} (insn #{:?})",
               dst_insn_ptr, insn_ptr);
    }
}

fn check_registers(insn: &ebpf::Insn, store: bool, insn_ptr: usize) {
    if insn.src > 10 {
        panic!("[Verifier] Error: invalid source register (insn #{:?})", insn_ptr);
    }

    match (insn.dst, store) {
        (0 ... 9, _) => {},
        (10, true)   => {},
        (10, false)  => panic!("[Verifier] Error: cannot write into register r10 (insn #{:?})",
                               insn_ptr),
        (_, _)       => panic!("[Verifier] Error: invalid destination register (insn #{:?})",
                               insn_ptr)
    }
}

pub fn check(prog: &[u8]) -> bool {
    check_prog_len(prog);

    let mut insn_ptr:usize = 0;
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        let insn = ebpf::get_insn(prog, insn_ptr);
        let mut store = false;

        match insn.opc {

            // BPF_LD class
            ebpf::LD_ABS_B   => { unimplemented!(); },
            ebpf::LD_ABS_H   => { unimplemented!(); },
            ebpf::LD_ABS_W   => { unimplemented!(); },
            ebpf::LD_ABS_DW  => { unimplemented!(); },
            ebpf::LD_IND_B   => { unimplemented!(); },
            ebpf::LD_IND_H   => { unimplemented!(); },
            ebpf::LD_IND_W   => { unimplemented!(); },
            ebpf::LD_IND_DW  => { unimplemented!(); },

            // BPF_LDX class
            ebpf::LD_DW_IMM  => {
                store = true;
                check_load_dw(prog, insn_ptr);
                insn_ptr += 1;
            },
            ebpf::LD_B_REG   => {},
            ebpf::LD_H_REG   => {},
            ebpf::LD_W_REG   => {},
            ebpf::LD_DW_REG  => {},

            // BPF_ST class
            ebpf::ST_B_IMM   => store = true,
            ebpf::ST_H_IMM   => store = true,
            ebpf::ST_W_IMM   => store = true,
            ebpf::ST_DW_IMM  => store = true,

            // BPF_STX class
            ebpf::ST_B_REG   => store = true,
            ebpf::ST_H_REG   => store = true,
            ebpf::ST_W_REG   => store = true,
            ebpf::ST_DW_REG  => store = true,
            ebpf::ST_W_XADD  => { unimplemented!(); },
            ebpf::ST_DW_XADD => { unimplemented!(); },

            // BPF_ALU class
            ebpf::ADD32_IMM  => {},
            ebpf::ADD32_REG  => {},
            ebpf::SUB32_IMM  => {},
            ebpf::SUB32_REG  => {},
            ebpf::MUL32_IMM  => {},
            ebpf::MUL32_REG  => {},
            ebpf::DIV32_IMM  => { check_imm_nonzero(&insn, insn_ptr); },
            ebpf::DIV32_REG  => {},
            ebpf::OR32_IMM   => {},
            ebpf::OR32_REG   => {},
            ebpf::AND32_IMM  => {},
            ebpf::AND32_REG  => {},
            ebpf::LSH32_IMM  => {},
            ebpf::LSH32_REG  => {},
            ebpf::RSH32_IMM  => {},
            ebpf::RSH32_REG  => {},
            ebpf::NEG32      => {},
            ebpf::MOD32_IMM  => { check_imm_nonzero(&insn, insn_ptr); },
            ebpf::MOD32_REG  => {},
            ebpf::XOR32_IMM  => {},
            ebpf::XOR32_REG  => {},
            ebpf::MOV32_IMM  => {},
            ebpf::MOV32_REG  => {},
            ebpf::ARSH32_IMM => {},
            ebpf::ARSH32_REG => {},
            ebpf::LE         => { check_imm_endian(&insn, insn_ptr); },
            ebpf::BE         => { check_imm_endian(&insn, insn_ptr); },

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => {},
            ebpf::ADD64_REG  => {},
            ebpf::SUB64_IMM  => {},
            ebpf::SUB64_REG  => {},
            ebpf::MUL64_IMM  => { check_imm_nonzero(&insn, insn_ptr); },
            ebpf::MUL64_REG  => {},
            ebpf::DIV64_IMM  => { check_imm_nonzero(&insn, insn_ptr); },
            ebpf::DIV64_REG  => {},
            ebpf::OR64_IMM   => {},
            ebpf::OR64_REG   => {},
            ebpf::AND64_IMM  => {},
            ebpf::AND64_REG  => {},
            ebpf::LSH64_IMM  => {},
            ebpf::LSH64_REG  => {},
            ebpf::RSH64_IMM  => {},
            ebpf::RSH64_REG  => {},
            ebpf::NEG64      => {},
            ebpf::MOD64_IMM  => {},
            ebpf::MOD64_REG  => {},
            ebpf::XOR64_IMM  => {},
            ebpf::XOR64_REG  => {},
            ebpf::MOV64_IMM  => {},
            ebpf::MOV64_REG  => {},
            ebpf::ARSH64_IMM => {},
            ebpf::ARSH64_REG => {},

            // BPF_JMP class
            ebpf::JA         => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JEQ_IMM    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JEQ_REG    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JGT_IMM    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JGT_REG    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JGE_IMM    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JGE_REG    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSET_IMM   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSET_REG   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JNE_IMM    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JNE_REG    => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSGT_IMM   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSGT_REG   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSGE_IMM   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::JSGE_REG   => { check_jmp_offset(prog, insn_ptr); },
            ebpf::CALL       => {},
            ebpf::TAIL_CALL  => { unimplemented!() },
            ebpf::EXIT       => {},

            _                => {
                panic!("[Verifier] Error: unknown eBPF opcode {:#2x} (insn #{:?})",
                       insn.opc, insn_ptr);
            },
        }

        check_registers(&insn, store, insn_ptr);

        insn_ptr += 1;
    }

    // insn_ptr should now be equal to number of instructions.
    if insn_ptr != prog.len() / ebpf::INSN_SIZE {
        panic!("[Verifier] Error: jumped out of code to #{:?}", insn_ptr);
    }

    true
}
