// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// RISC-V 64-bit JIT backend for eBPF
// Adapted from StarryOS eBPF JIT implementation

#[cfg(not(feature = "std"))]
use crate::ErrorKind;
use crate::{Error, HashMap, Vec, ebpf, format, vec};
use core::mem;

const PAGE_SIZE: usize = 4096;
const NUM_PAGES: usize = 5;

const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;

const RV_ZERO: u32 = 0;
const RV_RA: u32 = 1;
const RV_SP: u32 = 2;
const RV_GP: u32 = 3;
const RV_TP: u32 = 4;
const RV_T0: u32 = 5;
const RV_T1: u32 = 6;
const RV_T2: u32 = 7;
const RV_S1: u32 = 9;
const RV_A0: u32 = 10;
const RV_A1: u32 = 11;
const RV_A2: u32 = 12;
const RV_A3: u32 = 13;
const RV_A4: u32 = 14;
const RV_A5: u32 = 15;
const RV_S2: u32 = 18;
const RV_S3: u32 = 19;
const RV_S4: u32 = 20;
const RV_S5: u32 = 21;
const RV_T3: u32 = 28;
const RV_T4: u32 = 29;
const RV_T5: u32 = 30;
const RV_T6: u32 = 31;

const BPF_STACK_SIZE: usize = ebpf::STACK_SIZE;
const CALLEE_SAVED_SIZE: usize = 48;
const FRAME_SIZE: usize = BPF_STACK_SIZE + CALLEE_SAVED_SIZE;

const REGISTER_MAP_SIZE: usize = 11;
const REGISTER_MAP: [u32; REGISTER_MAP_SIZE] = [
    RV_A0, RV_A1, RV_A2, RV_A3, RV_A4, RV_A5, RV_S1, RV_S2, RV_S3, RV_S4, RV_S5,
];

fn map_register(r: u8) -> u32 {
    REGISTER_MAP[r as usize % REGISTER_MAP_SIZE]
}

#[derive(Copy, Clone)]
struct Jump {
    offset_loc: usize,
    target_pc: isize,
}

pub(crate) struct RiscV64Compiler {
    pc_locs: Vec<usize>,
    special_targets: HashMap<isize, usize>,
    jumps: Vec<Jump>,
}

impl RiscV64Compiler {
    fn new() -> RiscV64Compiler {
        RiscV64Compiler {
            pc_locs: vec![],
            jumps: vec![],
            special_targets: HashMap::new(),
        }
    }

    fn emit4(&self, mem: &mut JitMemory, data: u32) {
        let bytes = data.to_le_bytes();
        mem.contents[mem.offset] = bytes[0];
        mem.contents[mem.offset + 1] = bytes[1];
        mem.contents[mem.offset + 2] = bytes[2];
        mem.contents[mem.offset + 3] = bytes[3];
        mem.offset += 4;
    }

    fn set_anchor(&mut self, mem: &mut JitMemory, target_pc: isize) {
        self.special_targets.insert(target_pc, mem.offset);
    }

    // RISC-V instruction encoding helpers
    fn emit_r(
        &self,
        mem: &mut JitMemory,
        funct7: u32,
        rs2: u32,
        rs1: u32,
        funct3: u32,
        rd: u32,
        opcode: u32,
    ) {
        self.emit4(
            mem,
            (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode,
        );
    }

    fn emit_i(&self, mem: &mut JitMemory, imm: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) {
        self.emit4(
            mem,
            (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode,
        );
    }

    fn emit_s(&self, mem: &mut JitMemory, imm: u32, rs2: u32, rs1: u32, funct3: u32) {
        self.emit4(
            mem,
            ((imm >> 5) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | ((imm & 0x1f) << 7)
                | 0x23,
        );
    }

    fn emit_b(&self, mem: &mut JitMemory, imm: u32, rs2: u32, rs1: u32, funct3: u32) {
        let bit12 = (imm >> 12) & 1;
        let bits10_5 = (imm >> 5) & 0x3f;
        let bits4_1 = (imm >> 1) & 0xf;
        let bit11 = (imm >> 11) & 1;
        self.emit4(
            mem,
            (bit12 << 31)
                | (bits10_5 << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | (bits4_1 << 8)
                | (bit11 << 7)
                | 0x63,
        );
    }

    fn emit_u(&self, mem: &mut JitMemory, imm: u32, rd: u32, opcode: u32) {
        self.emit4(mem, (imm << 12) | (rd << 7) | opcode);
    }

    // ALU operations
    fn emit_add(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 0, rd, 0x33);
    }

    fn emit_addw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 0, rd, 0x3b);
    }

    fn emit_sub(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0x20, rs2, rs1, 0, rd, 0x33);
    }

    fn emit_subw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0x20, rs2, rs1, 0, rd, 0x3b);
    }

    fn emit_mul(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 0, rd, 0x33);
    }

    fn emit_mulw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 0, rd, 0x3b);
    }

    fn emit_divu(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 5, rd, 0x33);
    }

    fn emit_divuw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 5, rd, 0x3b);
    }

    fn emit_remu(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 7, rd, 0x33);
    }

    fn emit_remuw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 1, rs2, rs1, 7, rd, 0x3b);
    }

    fn emit_and(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 7, rd, 0x33);
    }

    fn emit_andw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 7, rd, 0x3b);
    }

    fn emit_or(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 6, rd, 0x33);
    }

    fn emit_orw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 6, rd, 0x3b);
    }

    fn emit_xor(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 4, rd, 0x33);
    }

    fn emit_xorw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 4, rd, 0x3b);
    }

    fn emit_sll(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 1, rd, 0x33);
    }

    fn emit_sllw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 1, rd, 0x3b);
    }

    fn emit_srl(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 5, rd, 0x33);
    }

    fn emit_srlw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0, rs2, rs1, 5, rd, 0x3b);
    }

    fn emit_sra(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0x20, rs2, rs1, 5, rd, 0x33);
    }

    fn emit_sraw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(mem, 0x20, rs2, rs1, 5, rd, 0x3b);
    }

    fn emit_neg(&self, mem: &mut JitMemory, rd: u32, rs: u32) {
        self.emit_sub(mem, rd, RV_ZERO, rs);
    }

    fn emit_negw(&self, mem: &mut JitMemory, rd: u32, rs: u32) {
        self.emit_subw(mem, rd, RV_ZERO, rs);
    }

    // Immediate ALU
    fn emit_addi(&self, mem: &mut JitMemory, rd: u32, rs1: u32, imm: i32) {
        if imm >= 0 && imm < 2048 || imm < 0 && imm >= -2048 {
            self.emit_i(mem, imm as u32, rs1, 0, rd, 0x13);
        } else {
            self.emit_load_imm(mem, RV_T1, imm as i64);
            self.emit_add(mem, rd, rs1, RV_T1);
        }
    }

    fn emit_addiw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, imm: i32) {
        self.emit_i(mem, imm as u32, rs1, 0, rd, 0x1b);
    }

    fn emit_andi(&self, mem: &mut JitMemory, rd: u32, rs1: u32, imm: i32) {
        self.emit_i(mem, imm as u32, rs1, 7, rd, 0x13);
    }

    fn emit_ori(&self, mem: &mut JitMemory, rd: u32, rs1: u32, imm: i32) {
        self.emit_i(mem, imm as u32, rs1, 6, rd, 0x13);
    }

    fn emit_xori(&self, mem: &mut JitMemory, rd: u32, rs1: u32, imm: i32) {
        self.emit_i(mem, imm as u32, rs1, 4, rd, 0x13);
    }

    fn emit_slli(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0, shamt & 0x3f, rs1, 1, rd, 0x13);
    }

    fn emit_slliw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0, shamt & 0x1f, rs1, 1, rd, 0x1b);
    }

    fn emit_srli(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0, shamt & 0x3f, rs1, 5, rd, 0x13);
    }

    fn emit_srliw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0, shamt & 0x1f, rs1, 5, rd, 0x1b);
    }

    fn emit_srai(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0x20, shamt & 0x3f, rs1, 5, rd, 0x13);
    }

    fn emit_sraiw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, shamt: u32) {
        self.emit_r(mem, 0x20, shamt & 0x1f, rs1, 5, rd, 0x1b);
    }

    // LUI
    fn emit_lui(&self, mem: &mut JitMemory, rd: u32, imm: u32) {
        self.emit_u(mem, imm & 0xfffff, rd, 0x37);
    }

    // Load/Store
    fn emit_ld(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 3, rd, 0x03);
    }

    fn emit_lw(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 2, rd, 0x03);
    }

    fn emit_lwu(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 6, rd, 0x03);
    }

    fn emit_lh(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 1, rd, 0x03);
    }

    fn emit_lhu(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 5, rd, 0x03);
    }

    fn emit_lb(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 4, rd, 0x03);
    }

    fn emit_lbu(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 4, rd, 0x03);
    }

    fn emit_sd(&self, mem: &mut JitMemory, rs2: u32, rs1: u32, off: i32) {
        self.emit_s(mem, off as u32, rs2, rs1, 3);
    }

    fn emit_sw(&self, mem: &mut JitMemory, rs2: u32, rs1: u32, off: i32) {
        self.emit_s(mem, off as u32, rs2, rs1, 2);
    }

    fn emit_sh(&self, mem: &mut JitMemory, rs2: u32, rs1: u32, off: i32) {
        self.emit_s(mem, off as u32, rs2, rs1, 1);
    }

    fn emit_sb(&self, mem: &mut JitMemory, rs2: u32, rs1: u32, off: i32) {
        self.emit_s(mem, off as u32, rs2, rs1, 0);
    }

    // Branches
    fn emit_beq(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 0);
    }

    fn emit_bne(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 1);
    }

    fn emit_bltu(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 6);
    }

    fn emit_bgeu(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 7);
    }

    fn emit_blt(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 4);
    }

    fn emit_bge(&self, mem: &mut JitMemory, rs1: u32, rs2: u32, off: u32) {
        self.emit_b(mem, off, rs2, rs1, 5);
    }

    // JALR (indirect jump)
    fn emit_jalr(&self, mem: &mut JitMemory, rd: u32, rs1: u32, off: i32) {
        self.emit_i(mem, off as u32, rs1, 0, rd, 0x67);
    }

    // Zero-extend 32-bit
    fn emit_zext32(&self, mem: &mut JitMemory, rd: u32) {
        self.emit_slli(mem, rd, rd, 32);
        self.emit_srli(mem, rd, rd, 32);
    }

    // Load 64-bit immediate (up to 7 instructions)
    fn emit_load_imm(&self, mem: &mut JitMemory, rd: u32, val: i64) {
        let val = val as u64;
        if val == 0 {
            self.emit_addi(mem, rd, RV_ZERO, 0);
            return;
        }
        if (val as i32) >= -2048 && (val as i32) < 2048 {
            self.emit_addi(mem, rd, RV_ZERO, val as i32);
            return;
        }
        if (val as u32) & 0xfff == 0 {
            let hi20 = (((val as u32).wrapping_add(0x800)) >> 12) & 0xFFFFF;
            self.emit_lui(mem, rd, hi20);
            return;
        }
        let lower = val as u32;
        let lower_lo12 = ((lower << 20) as i32) >> 20;
        let lower_lo12_u = lower_lo12 as u32;
        let lower_hi20 = (lower.wrapping_sub(lower_lo12_u).wrapping_add(0x800)) >> 12;
        let upper = (val >> 32) as u32;
        let upper_lo12 = ((upper << 20) as i32) >> 20;
        let upper_lo12_u = upper_lo12 as u32;
        let upper_hi20 = (upper.wrapping_sub(upper_lo12_u).wrapping_add(0x800)) >> 12;
        self.emit_lui(mem, rd, upper_hi20 & 0xFFFFF);
        self.emit_addiw(mem, rd, rd, upper_lo12);
        self.emit_slli(mem, rd, rd, 12);
        self.emit_lui(mem, RV_T1, lower_hi20 & 0xFFFFF);
        if lower_lo12_u != 0 {
            self.emit_addiw(mem, RV_T1, RV_T1, lower_lo12);
        }
        self.emit_add(mem, rd, rd, RV_T1);
    }

    // Load effective address for ST/STX/LDX with BPF stack pointer adjustment
    fn emit_effective_addr(&self, mem: &mut JitMemory, base: u32, off: i32, dst: u32) {
        let effective_off = if base == RV_S5 {
            off - CALLEE_SAVED_SIZE as i32
        } else {
            off
        };
        if effective_off >= -2048 && effective_off < 2048 {
            self.emit_addi(mem, dst, base, effective_off);
        } else {
            self.emit_load_imm(mem, dst, effective_off as i64);
            self.emit_add(mem, dst, base, dst);
        }
    }

    // Emit a jump (records for backfill)
    fn emit_jump(&mut self, mem: &mut JitMemory, target_pc: isize) {
        self.jumps.push(Jump {
            offset_loc: mem.offset,
            target_pc,
        });
        self.emit4(mem, 0x00000013); // NOP placeholder
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
    }

    // Emit conditional jump with inverted condition
    fn emit_cond_jump(
        &mut self,
        mem: &mut JitMemory,
        funct3: u32,
        rs1: u32,
        rs2: u32,
        target_pc: isize,
    ) {
        self.emit4(mem, 0x00000013); // NOP for AUIPC
        self.emit4(mem, 0x00000013); // NOP for load_imm64_padded
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013); // NOP for ADD
        // Inverted condition: skip the jump if condition is true
        let inv_funct3 = match funct3 {
            0 => 1, // BEQ -> BNE
            1 => 0, // BNE -> BEQ
            4 => 5, // BLT -> BGE
            5 => 4, // BGE -> BLT
            6 => 7, // BLTU -> BGEU
            7 => 6, // BGEU -> BLTU
            _ => funct3,
        };
        self.emit_b(mem, 40, rs2, rs1, inv_funct3);
        self.jumps.push(Jump {
            offset_loc: mem.offset,
            target_pc,
        });
        self.emit4(mem, 0x00000013); // NOP for AUIPC
        self.emit4(mem, 0x00000013); // NOP for load_imm64
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013);
        self.emit4(mem, 0x00000013); // NOP for ADD
        self.emit4(mem, 0x00000013); // NOP for JALR
    }

    fn resolve_jumps(&mut self, mem: &mut JitMemory) -> Result<(), Error> {
        for jump in &self.jumps {
            let target_loc = match self.special_targets.get(&jump.target_pc) {
                Some(&target) => target,
                None => {
                    if jump.target_pc < 0 || jump.target_pc as usize >= self.pc_locs.len() {
                        return Err(Error::other("[JIT riscv64] Error: unresolved jump target"));
                    }
                    self.pc_locs[jump.target_pc as usize]
                }
            };
            let pc = jump.offset_loc;
            let offset = target_loc as i64 - pc as i64;
            let auipc_off = offset;
            let jalr_off = offset - (auipc_off & !0xfff);
            let lo12 = (jalr_off as i32) & 0xfff;
            let hi20_plus_lo12 = auipc_off as u32;
            let hi20 = (hi20_plus_lo12.wrapping_sub(lo12 as u32).wrapping_add(0x800)) >> 12;
            let rd_tmp = RV_T3;
            let rd_jalr = RV_T4;
            self.emit_auipc_at(mem, pc, rd_tmp, hi20 & 0xFFFFF);
            self.emit_load_imm_at(mem, pc + 4, rd_jalr, jalr_off);
            self.emit_addi_at(mem, pc + 24, rd_tmp, rd_tmp, lo12);
            self.emit_jalr_at(mem, pc + 28, RV_ZERO, rd_tmp, 0);
        }
        Ok(())
    }

    fn emit_auipc_at(&self, mem: &mut JitMemory, offset: usize, rd: u32, imm: u32) {
        let insn = (imm << 12) | (rd << 7) | 0x17;
        let bytes = insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[offset + i] = bytes[i];
        }
    }

    fn emit_jalr_at(&self, mem: &mut JitMemory, offset: usize, rd: u32, rs1: u32, imm: i32) {
        let insn = ((imm as u32) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x67;
        let bytes = insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[offset + i] = bytes[i];
        }
    }

    fn emit_addi_at(&self, mem: &mut JitMemory, offset: usize, rd: u32, rs1: u32, imm: i32) {
        let insn = ((imm as u32) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x13;
        let bytes = insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[offset + i] = bytes[i];
        }
    }

    fn emit_load_imm_at(&self, mem: &mut JitMemory, start: usize, rd: u32, val: i64) {
        let val_u = val as u64;
        if val_u == 0 {
            let insn = (0u32 << 20) | (RV_ZERO << 15) | (0 << 12) | (rd << 7) | 0x13;
            let bytes = insn.to_le_bytes();
            for i in 0..4 {
                mem.contents[start + i] = bytes[i];
            }
            return;
        }
        if (val as i32) >= -2048 && (val as i32) < 2048 {
            let insn = ((val as u32) << 20) | (RV_ZERO << 15) | (0 << 12) | (rd << 7) | 0x13;
            let bytes = insn.to_le_bytes();
            for i in 0..4 {
                mem.contents[start + i] = bytes[i];
            }
            return;
        }
        let upper = (val_u >> 32) as u32;
        let lower = val_u as u32;
        let upper_lo12 = ((upper << 20) as i32) >> 20;
        let upper_hi20 =
            ((upper.wrapping_sub(upper_lo12 as u32).wrapping_add(0x800)) >> 12) & 0xFFFFF;
        let lower_lo12 = ((lower << 20) as i32) >> 20;
        let lower_hi20 =
            ((lower.wrapping_sub(lower_lo12 as u32).wrapping_add(0x800)) >> 12) & 0xFFFFF;
        let mut off = start;
        let lui_insn = (upper_hi20 << 12) | (rd << 7) | 0x37;
        let bytes = lui_insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[off + i] = bytes[i];
        }
        off += 4;
        let addiw_insn = ((upper_lo12 as u32) << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x1b;
        let bytes = addiw_insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[off + i] = bytes[i];
        }
        off += 4;
        let slli_insn = (0u32 << 25) | (12 << 20) | (rd << 15) | (1 << 12) | (rd << 7) | 0x13;
        let bytes = slli_insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[off + i] = bytes[i];
        }
        off += 4;
        let lui_t1 = (lower_hi20 << 12) | (RV_T1 << 7) | 0x37;
        let bytes = lui_t1.to_le_bytes();
        for i in 0..4 {
            mem.contents[off + i] = bytes[i];
        }
        off += 4;
        if lower_lo12 as u32 != 0 {
            let addiw_t1 =
                ((lower_lo12 as u32) << 20) | (RV_T1 << 15) | (0 << 12) | (RV_T1 << 7) | 0x1b;
            let bytes = addiw_t1.to_le_bytes();
            for i in 0..4 {
                mem.contents[off + i] = bytes[i];
            }
        }
        off += 4;
        let add_insn = (0u32 << 25) | (RV_T1 << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x33;
        let bytes = add_insn.to_le_bytes();
        for i in 0..4 {
            mem.contents[off + i] = bytes[i];
        }
    }

    fn jit_compile(
        &mut self,
        mem: &mut JitMemory,
        prog: &[u8],
        use_mbuff: bool,
        update_data_ptr: bool,
        helpers: &HashMap<u32, ebpf::Helper>,
    ) -> Result<(), Error> {
        // Prologue: save callee-saved registers
        self.emit_addi(mem, RV_SP, RV_SP, -(FRAME_SIZE as i32));
        self.emit_sd(mem, RV_RA, RV_SP, 0);
        self.emit_sd(mem, RV_S1, RV_SP, 8);
        self.emit_sd(mem, RV_S2, RV_SP, 16);
        self.emit_sd(mem, RV_S3, RV_SP, 24);
        self.emit_sd(mem, RV_S4, RV_SP, 32);
        self.emit_sd(mem, RV_S5, RV_SP, 40);

        // RV ABI: A0=arg1, A1=arg2, A2=arg3, A3=arg4, A4=arg5, A5=arg6
        // rbpf calling convention:
        //   A0(FixedMbuff): mbuff, A1: mbuff_len, A2: mem, A3: mem_len, A4: mem_offset, A5: mem_end_offset
        //   A0(Raw): mem, A1: mem_len
        // BPF: r1=arg1, r2=arg2, r3=arg3, r4=arg4, r5=arg5

        // Save mem pointer to BPF r10 (stack pointer)
        match (use_mbuff, update_data_ptr) {
            (false, _) => {
                // EbpfVmRaw: A0=mem, A1=mem_len
                // BPF r1 already = A0 = mem pointer
            }
            (true, false) => {
                // EbpfVmMbuff: A0=mbuff
                // BPF r1 = mbuff
            }
            (true, true) => {
                // EbpfVmFixedMbuff: update mem/mem_end in mbuff
                // A0=mbuff, A4=mem_offset, A5=mem_end_offset, A2=mem, A3=mem_len
                self.emit_add(mem, RV_A4, RV_A0); // tmp = mbuff + mem_offset
                self.emit_sd(mem, RV_A2, RV_A4, 0); // store mem at mbuff+mem_offset
                self.emit_add(mem, RV_A5, RV_A0); // tmp = mbuff + mem_end_offset
                self.emit_add(mem, RV_T1, RV_A2, RV_A3); // mem_end = mem + mem_len
                self.emit_sd(mem, RV_T1, RV_A5, 0); // store mem_end
            }
        }

        // BPF r10 = stack pointer (after callee-saved area)
        self.emit_addi(mem, map_register(10), RV_SP, CALLEE_SAVED_SIZE as i32);

        // Set up exit anchor
        self.set_anchor(mem, TARGET_PC_EXIT);

        self.pc_locs = vec![0; prog.len() / ebpf::INSN_SIZE + 1];

        let mut insn_ptr: usize = 0;
        while insn_ptr * ebpf::INSN_SIZE < prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);
            self.pc_locs[insn_ptr] = mem.offset;

            let dst = map_register(insn.dst);
            let src = map_register(insn.src);
            let target_pc = insn_ptr as isize + insn.off as isize + 1;
            let use_imm = (insn.opc & ebpf::BPF_X) == 0;

            match insn.opc {
                // LD_DW_IMM
                ebpf::LD_DW_IMM => {
                    insn_ptr += 1;
                    let next = ebpf::get_insn(prog, insn_ptr);
                    let imm = (insn.imm as u32) as u64 | ((next.imm as u64) << 32);
                    self.emit_load_imm(mem, dst, imm as i64);
                }

                // LDX
                ebpf::LD_B_REG => {
                    self.emit_effectiveaddr(mem, src, insn.off as i32, RV_T1);
                    self.emit_lb(mem, dst, RV_T1, 0);
                }
                ebpf::LD_H_REG => {
                    self.emit_effectiveaddr(mem, src, insn.off as i32, RV_T1);
                    self.emit_lhu(mem, dst, RV_T1, 0);
                }
                ebpf::LD_W_REG => {
                    self.emit_effectiveaddr(mem, src, insn.off as i32, RV_T1);
                    self.emit_lwu(mem, dst, RV_T1, 0);
                }
                ebpf::LD_DW_REG => {
                    self.emit_effectiveaddr(mem, src, insn.off as i32, RV_T1);
                    self.emit_ld(mem, dst, RV_T1, 0);
                }

                // ST
                ebpf::ST_B_IMM => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_load_imm(mem, RV_T2, insn.imm as i64);
                    self.emit_sb(mem, RV_T2, RV_T1, 0);
                }
                ebpf::ST_H_IMM => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_load_imm(mem, RV_T2, insn.imm as i64);
                    self.emit_sh(mem, RV_T2, RV_T1, 0);
                }
                ebpf::ST_W_IMM => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_load_imm(mem, RV_T2, insn.imm as i64);
                    self.emit_sw(mem, RV_T2, RV_T1, 0);
                }
                ebpf::ST_DW_IMM => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_load_imm(mem, RV_T2, insn.imm as i64);
                    self.emit_sd(mem, RV_T2, RV_T1, 0);
                }

                // STX
                ebpf::ST_B_REG => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_sb(mem, src, RV_T1, 0);
                }
                ebpf::ST_H_REG => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_sh(mem, src, RV_T1, 0);
                }
                ebpf::ST_W_REG => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_sw(mem, src, RV_T1, 0);
                }
                ebpf::ST_DW_REG => {
                    self.emit_effectiveaddr(mem, dst, insn.off as i32, RV_T1);
                    self.emit_sd(mem, src, RV_T1, 0);
                }

                // ALU32
                ebpf::ADD32_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addiw(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_addw(mem, dst, dst, RV_T1);
                    }
                    self.emit_zext32(mem, dst);
                }
                ebpf::ADD32_REG => {
                    self.emit_addw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::SUB32_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addiw(mem, dst, dst, -(insn.imm));
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_subw(mem, dst, dst, RV_T1);
                    }
                    self.emit_zext32(mem, dst);
                }
                ebpf::SUB32_REG => {
                    self.emit_subw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::MUL32_IMM | ebpf::MUL32_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_mulw(mem, dst, dst, s);
                    self.emit_zext32(mem, dst);
                }
                ebpf::DIV32_IMM | ebpf::DIV32_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_beq(mem, s, RV_ZERO, 20);
                    self.emit_divuw(mem, dst, dst, s);
                    self.emit_jalr(mem, RV_ZERO, RV_RA, 0);
                    self.emit_addi(mem, dst, RV_ZERO, 0);
                    self.emit_zext32(mem, dst);
                }
                ebpf::MOD32_IMM | ebpf::MOD32_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_beq(mem, s, RV_ZERO, 8);
                    self.emit_remuw(mem, dst, dst, s);
                    self.emit_zext32(mem, dst);
                }
                ebpf::OR32_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_ori(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_orw(mem, dst, dst, RV_T1);
                    }
                    self.emit_zext32(mem, dst);
                }
                ebpf::OR32_REG => {
                    self.emit_orw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::AND32_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_andi(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_andw(mem, dst, dst, RV_T1);
                    }
                    self.emit_zext32(mem, dst);
                }
                ebpf::AND32_REG => {
                    self.emit_andw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::LSH32_IMM => {
                    self.emit_slliw(mem, dst, dst, (insn.imm as u32) & 0x1f);
                    self.emit_zext32(mem, dst);
                }
                ebpf::LSH32_REG => {
                    self.emit_sllw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::RSH32_IMM => {
                    self.emit_srliw(mem, dst, dst, (insn.imm as u32) & 0x1f);
                    self.emit_zext32(mem, dst);
                }
                ebpf::RSH32_REG => {
                    self.emit_srlw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::NEG32 => {
                    self.emit_negw(mem, dst, dst);
                    self.emit_zext32(mem, dst);
                }
                ebpf::XOR32_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_xori(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_xorw(mem, dst, dst, RV_T1);
                    }
                    self.emit_zext32(mem, dst);
                }
                ebpf::XOR32_REG => {
                    self.emit_xorw(mem, dst, dst, src);
                    self.emit_zext32(mem, dst);
                }
                ebpf::MOV32_IMM => {
                    self.emit_load_imm(mem, dst, insn.imm as i64);
                    self.emit_zext32(mem, dst);
                }
                ebpf::MOV32_REG => {
                    self.emit_addi(mem, dst, src, 0);
                    self.emit_zext32(mem, dst);
                }
                ebpf::ARSH32_IMM => {
                    self.emit_sraiw(mem, dst, dst, (insn.imm as u32) & 0x1f);
                }
                ebpf::ARSH32_REG => {
                    self.emit_sraw(mem, dst, dst, src);
                }
                ebpf::LE => {} // no-op on little-endian
                ebpf::BE => {
                    match insn.imm {
                        16 => {
                            // Swap two bytes using RV_T1 and RV_T2
                            let tmp = RV_T1;
                            let tmp2 = RV_T2;
                            // byte 0 -> position 1
                            self.emit_andi(mem, tmp2, dst, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 8);
                            // byte 1 -> position 0
                            self.emit_srli(mem, tmp, dst, 8);
                            self.emit_andi(mem, tmp, tmp, 0xff);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_addi(mem, dst, tmp, 0);
                            // Zero-extend to 16 bits
                            self.emit_slli(mem, dst, dst, 48);
                            self.emit_srli(mem, dst, dst, 48);
                        }
                        32 => {
                            // Swap four bytes using RV_T1 and RV_T2
                            let tmp = RV_T1;
                            let tmp2 = RV_T2;
                            self.emit_addi(mem, tmp, RV_ZERO, 0);
                            // byte 0 -> position 3
                            self.emit_andi(mem, tmp2, dst, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 24);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            // byte 1 -> position 2
                            self.emit_srli(mem, tmp2, dst, 8);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 16);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            // byte 2 -> position 1
                            self.emit_srli(mem, tmp2, dst, 16);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 8);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            // byte 3 -> position 0
                            self.emit_srli(mem, tmp2, dst, 24);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_or(mem, dst, tmp, tmp2);
                            // Zero-extend to 32 bits
                            self.emit_slli(mem, dst, dst, 32);
                            self.emit_srli(mem, dst, dst, 32);
                        }
                        64 => {
                            // Reverse bytes: use 8 iterations of shift+and+or
                            let tmp = RV_T1;
                            let tmp2 = RV_T2;
                            self.emit_addi(mem, tmp, RV_ZERO, 0);
                            self.emit_andi(mem, tmp2, dst, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 56);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 8);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 48);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 16);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 40);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 24);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 32);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 32);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 24);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 40);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 16);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 48);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_slli(mem, tmp2, tmp2, 8);
                            self.emit_or(mem, tmp, tmp, tmp2);
                            self.emit_srli(mem, tmp2, dst, 56);
                            self.emit_andi(mem, tmp2, tmp2, 0xff);
                            self.emit_or(mem, dst, tmp, tmp2);
                        }
                        _ => unreachable!(),
                    }
                }

                // ALU64
                ebpf::ADD64_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_add(mem, dst, dst, RV_T1);
                    }
                }
                ebpf::ADD64_REG => self.emit_add(mem, dst, dst, src),
                ebpf::SUB64_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, dst, dst, -(insn.imm));
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_sub(mem, dst, dst, RV_T1);
                    }
                }
                ebpf::SUB64_REG => self.emit_sub(mem, dst, dst, src),
                ebpf::MUL64_IMM | ebpf::MUL64_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_mul(mem, dst, dst, s);
                }
                ebpf::DIV64_IMM | ebpf::DIV64_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_beq(mem, s, RV_ZERO, 20);
                    self.emit_divu(mem, dst, dst, s);
                    self.emit_jalr(mem, RV_ZERO, RV_RA, 0);
                    self.emit_addi(mem, dst, RV_ZERO, 0);
                }
                ebpf::MOD64_IMM | ebpf::MOD64_REG => {
                    if use_imm {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    let s = if use_imm { RV_T1 } else { src };
                    self.emit_beq(mem, s, RV_ZERO, 8);
                    self.emit_remu(mem, dst, dst, s);
                }
                ebpf::OR64_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_ori(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_or(mem, dst, dst, RV_T1);
                    }
                }
                ebpf::OR64_REG => self.emit_or(mem, dst, dst, src),
                ebpf::AND64_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_andi(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_and(mem, dst, dst, RV_T1);
                    }
                }
                ebpf::AND64_REG => self.emit_and(mem, dst, dst, src),
                ebpf::LSH64_IMM => self.emit_slli(mem, dst, dst, (insn.imm as u32) & 0x3f),
                ebpf::LSH64_REG => self.emit_sll(mem, dst, dst, src),
                ebpf::RSH64_IMM => self.emit_srli(mem, dst, dst, (insn.imm as u32) & 0x3f),
                ebpf::RSH64_REG => self.emit_srl(mem, dst, dst, src),
                ebpf::NEG64 => self.emit_neg(mem, dst, dst),
                ebpf::XOR64_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_xori(mem, dst, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_xor(mem, dst, dst, RV_T1);
                    }
                }
                ebpf::XOR64_REG => self.emit_xor(mem, dst, dst, src),
                ebpf::MOV64_IMM => self.emit_load_imm(mem, dst, insn.imm as i64),
                ebpf::MOV64_REG => self.emit_addi(mem, dst, src, 0),
                ebpf::ARSH64_IMM => self.emit_srai(mem, dst, dst, (insn.imm as u32) & 0x3f),
                ebpf::ARSH64_REG => self.emit_sra(mem, dst, dst, src),

                // JMP
                ebpf::JA => self.emit_jump(mem, target_pc),
                ebpf::EXIT => {
                    // Jump to epilogue
                    self.emit_jump(mem, TARGET_PC_EXIT);
                }

                // JMP conditional 64-bit
                ebpf::JEQ_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 0, dst, RV_T1, target_pc);
                }
                ebpf::JEQ_REG => self.emit_cond_jump(mem, 0, dst, src, target_pc),
                ebpf::JGT_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 6, dst, RV_T1, target_pc);
                }
                ebpf::JGT_REG => self.emit_cond_jump(mem, 6, dst, src, target_pc),
                ebpf::JGE_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 7, dst, RV_T1, target_pc);
                }
                ebpf::JGE_REG => self.emit_cond_jump(mem, 7, dst, src, target_pc),
                ebpf::JLT_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 6, RV_T1, dst, target_pc);
                }
                ebpf::JLT_REG => self.emit_cond_jump(mem, 6, src, dst, target_pc),
                ebpf::JLE_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 7, RV_T1, dst, target_pc);
                }
                ebpf::JLE_REG => self.emit_cond_jump(mem, 7, src, dst, target_pc),
                ebpf::JSET_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_andi(mem, RV_T1, dst, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                        self.emit_and(mem, RV_T1, dst, RV_T1);
                    }
                    self.emit_cond_jump(mem, 1, RV_T1, RV_ZERO, target_pc);
                }
                ebpf::JSET_REG => {
                    self.emit_and(mem, RV_T1, dst, src);
                    self.emit_cond_jump(mem, 1, RV_T1, RV_ZERO, target_pc);
                }
                ebpf::JNE_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 1, dst, RV_T1, target_pc);
                }
                ebpf::JNE_REG => self.emit_cond_jump(mem, 1, dst, src, target_pc),
                ebpf::JSGT_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 4, RV_T1, dst, target_pc);
                }
                ebpf::JSGT_REG => self.emit_cond_jump(mem, 4, src, dst, target_pc),
                ebpf::JSGE_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 5, dst, RV_T1, target_pc);
                }
                ebpf::JSGE_REG => self.emit_cond_jump(mem, 5, dst, src, target_pc),
                ebpf::JSLT_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 4, dst, RV_T1, target_pc);
                }
                ebpf::JSLT_REG => self.emit_cond_jump(mem, 4, dst, src, target_pc),
                ebpf::JSLE_IMM => {
                    if insn.imm >= -2048 && insn.imm < 2048 {
                        self.emit_addi(mem, RV_T1, RV_ZERO, insn.imm);
                    } else {
                        self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    }
                    self.emit_cond_jump(mem, 5, RV_T1, dst, target_pc);
                }
                ebpf::JSLE_REG => self.emit_cond_jump(mem, 5, src, dst, target_pc),

                // JMP32 conditional
                ebpf::JEQ_IMM32 => {
                    self.emit_load_imm(mem, RV_T1, insn.imm as i64);
                    self.emit_zext32(mem, RV_T1);
                    self.emit_andi(mem, RV_T2, dst, 0);
                    self.emit_addi(mem, RV_T2, RV_T2, 0);
                    self.emit_zext32(mem, RV_T2);
                    self.emit_cond_jump(mem, 0, RV_T2, RV_T1, target_pc);
                }
                ebpf::JEQ_REG32 => {
                    self.emit_addi(mem, RV_T1, src, 0);
                    self.emit_zext32(mem, RV_T1);
                    self.emit_addi(mem, RV_T2, dst, 0);
                    self.emit_zext32(mem, RV_T2);
                    self.emit_cond_jump(mem, 0, RV_T2, RV_T1, target_pc);
                }
                ebpf::JGT_IMM32
                | ebpf::JGT_REG32
                | ebpf::JGE_IMM32
                | ebpf::JGE_REG32
                | ebpf::JLT_IMM32
                | ebpf::JLT_REG32
                | ebpf::JLE_IMM32
                | ebpf::JLE_REG32
                | ebpf::JSET_IMM32
                | ebpf::JSET_REG32
                | ebpf::JNE_IMM32
                | ebpf::JNE_REG32
                | ebpf::JSGT_IMM32
                | ebpf::JSGT_REG32
                | ebpf::JSGE_IMM32
                | ebpf::JSGE_REG32
                | ebpf::JSLT_IMM32
                | ebpf::JSLT_REG32
                | ebpf::JSLE_IMM32
                | ebpf::JSLE_REG32 => {
                    return Err(Error::other(format!(
                        "[JIT riscv64] Error: JMP32 opcode {:#2x} not yet implemented (insn #{insn_ptr})",
                        insn.opc
                    )));
                }

                // CALL
                ebpf::BPF_CALL => match insn.src {
                    0x0 => {
                        if let Some(&helper) = helpers.get(&(insn.imm as u32)) {
                            let fn_ptr = helper as usize;
                            self.emit_load_imm(mem, RV_T1, fn_ptr as i64);
                            self.emit_jalr(mem, RV_RA, RV_T1, 0);
                        } else {
                            return Err(Error::other(format!(
                                "[JIT riscv64] Error: unknown helper {:#x}",
                                insn.imm as u32
                            )));
                        }
                    }
                    0x1 => {
                        return Err(Error::other(
                            "[JIT riscv64] Error: BPF-to-BPF calls not supported",
                        ));
                    }
                    _ => {
                        return Err(Error::other(format!(
                            "[JIT riscv64] Error: unexpected call type #{:?}",
                            insn.src
                        )));
                    }
                },
                ebpf::TAIL_CALL => {
                    unimplemented!()
                }

                // LD_ABS/LD_IND - not commonly used, placeholder
                ebpf::LD_ABS_B
                | ebpf::LD_ABS_H
                | ebpf::LD_ABS_W
                | ebpf::LD_ABS_DW
                | ebpf::LD_IND_B
                | ebpf::LD_IND_H
                | ebpf::LD_IND_W
                | ebpf::LD_IND_DW => {
                    return Err(Error::other(
                        "[JIT riscv64] Error: LD_ABS/LD_IND not supported",
                    ));
                }

                ebpf::ST_W_XADD | ebpf::ST_DW_XADD => unimplemented!(),

                _ => {
                    return Err(Error::other(format!(
                        "[JIT riscv64] Error: unknown eBPF opcode {:#2x} (insn #{insn_ptr})",
                        insn.opc
                    )));
                }
            }

            insn_ptr += 1;
        }

        // Epilogue anchor
        self.set_anchor(mem, TARGET_PC_EXIT);

        // Epilogue: restore callee-saved and return
        self.emit_ld(mem, RV_RA, RV_SP, 0);
        self.emit_ld(mem, RV_S1, RV_SP, 8);
        self.emit_ld(mem, RV_S2, RV_SP, 16);
        self.emit_ld(mem, RV_S3, RV_SP, 24);
        self.emit_ld(mem, RV_S4, RV_SP, 32);
        self.emit_ld(mem, RV_S5, RV_SP, 40);
        self.emit_addi(mem, RV_SP, RV_SP, FRAME_SIZE as i32);
        self.emit_jalr(mem, RV_ZERO, RV_RA, 0);

        self.resolve_jumps(mem)?;
        Ok(())
    }
}

pub fn create_jit_memory<'a>(
    prog: &[u8],
    helpers: &HashMap<u32, ebpf::Helper>,
    use_mbuff: bool,
    update_data_ptr: bool,
) -> Result<JitMemory<'a>, Error> {
    let size = NUM_PAGES * PAGE_SIZE;
    let contents = unsafe {
        let layout = std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            return Err(Error::from(std::io::ErrorKind::OutOfMemory));
        }
        libc::mprotect(ptr.cast(), size, libc::PROT_EXEC | libc::PROT_WRITE);
        std::slice::from_raw_parts_mut(ptr, size)
    };

    let mut mem = JitMemory {
        contents,
        write_enabled: true,
        #[cfg(feature = "std")]
        layout: std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE),
        offset: 0,
    };

    let mut compiler = RiscV64Compiler::new();
    compiler.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
    Ok(mem)
}
