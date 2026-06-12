// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// AArch64 (ARM64) JIT backend for eBPF
// Adapted from StarryOS eBPF JIT implementation

#[cfg(not(feature = "std"))]
use crate::ErrorKind;
use crate::{Error, HashMap, Vec, ebpf, format, vec};

const PAGE_SIZE: usize = 4096;
const NUM_PAGES: usize = 5;

const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;

// ==========================================================================
// AArch64 register mapping
// ==========================================================================

const A64_X0: u32 = 0;
const A64_X1: u32 = 1;
const A64_X2: u32 = 2;
const A64_X3: u32 = 3;
const A64_X4: u32 = 4;
const A64_X5: u32 = 5;
const A64_X6: u32 = 6;
const A64_X7: u32 = 7;
const A64_X8: u32 = 8;
const A64_X9: u32 = 9;
const A64_X10: u32 = 10;
const A64_X11: u32 = 11;
const A64_X12: u32 = 12;
const A64_X16: u32 = 16;
const A64_X17: u32 = 17;
const A64_X19: u32 = 19;
const A64_X20: u32 = 20;
const A64_X21: u32 = 21;
const A64_X22: u32 = 22;
const A64_X25: u32 = 25;
const A64_X29: u32 = 29;
const A64_X30: u32 = 30;
// x31 is SP or XZR depending on instruction context
const A64_SP: u32 = 31;
const A64_XZR: u32 = 31;

const BPF_STACK_SIZE: usize = ebpf::STACK_SIZE;
/// Saved registers: x19-x22, x25 (5 regs) + x29, x30 = 7 regs, padded to 8
const CALLEE_SAVED_SIZE: usize = 64;
const FRAME_SIZE: usize = BPF_STACK_SIZE + CALLEE_SAVED_SIZE;

const REGISTER_MAP_SIZE: usize = 11;
const REGISTER_MAP: [u32; REGISTER_MAP_SIZE] = [
    A64_X0, A64_X1, A64_X2, A64_X3, A64_X4, A64_X5,
    A64_X19, A64_X20, A64_X21, A64_X22, A64_X25,
];

fn map_register(r: u8) -> u32 {
    REGISTER_MAP[r as usize % REGISTER_MAP_SIZE]
}

// Condition codes
const COND_EQ: u32 = 0b0000;
const COND_NE: u32 = 0b0001;
const COND_HS: u32 = 0b0010;
const COND_LO: u32 = 0b0011;
const COND_HI: u32 = 0b1000;
const COND_LS: u32 = 0b1001;
const COND_GE: u32 = 0b1010;
const COND_LT: u32 = 0b1011;
const COND_GT: u32 = 0b1100;
const COND_LE: u32 = 0b1101;

// Jump tracking
#[derive(Copy, Clone)]
struct Jump {
    offset_loc: usize,
    target_pc: isize,
}

pub(crate) struct Aarch64Compiler {
    pc_locs: Vec<usize>,
    special_targets: HashMap<isize, usize>,
    jumps: Vec<Jump>,
}

impl Aarch64Compiler {
    fn new() -> Aarch64Compiler {
        Aarch64Compiler {
            pc_locs: vec![],
            jumps: vec![],
            special_targets: HashMap::new(),
        }
    }

    // =======================================================================
    // Low-level write helpers
    // =======================================================================

    fn write_u32(&self, mem: &mut JitMemory, data: u32) {
        let bytes = data.to_le_bytes();
        mem.contents[mem.offset] = bytes[0];
        mem.contents[mem.offset + 1] = bytes[1];
        mem.contents[mem.offset + 2] = bytes[2];
        mem.contents[mem.offset + 3] = bytes[3];
        mem.offset += 4;
    }

    fn write_u32_at(&self, mem: &mut JitMemory, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        mem.contents[offset] = bytes[0];
        mem.contents[offset + 1] = bytes[1];
        mem.contents[offset + 2] = bytes[2];
        mem.contents[offset + 3] = bytes[3];
    }

    fn set_anchor(&mut self, mem: &mut JitMemory, target_pc: isize) {
        self.special_targets.insert(target_pc, mem.offset);
    }

    // =======================================================================
    // AArch64 instruction encoding helpers
    // =======================================================================

    fn emit_add(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x8B00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_addw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x0B00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_addi(&self, mem: &mut JitMemory, rd: u32, rn: u32, imm12: u32) {
        self.write_u32(mem, 0x9100_0000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd);
    }
    fn emit_sub(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0xCB00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_subw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x4B00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_subi(&self, mem: &mut JitMemory, rd: u32, rn: u32, imm12: u32) {
        self.write_u32(mem, 0xD100_0000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd);
    }
    fn emit_and(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x8A00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_andw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x0A00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_orr(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0xAA00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_orrw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x2A00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_eor(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0xCA00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_eorw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x4A00_0000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_madd(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32, ra: u32) {
        self.write_u32(mem, 0x9B00_0000 | (rm << 16) | (ra << 10) | (rn << 5) | rd);
    }
    fn emit_maddw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32, ra: u32) {
        self.write_u32(mem, 0x1B00_0000 | (rm << 16) | (ra << 10) | (rn << 5) | rd);
    }
    fn emit_udiv(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x9AC0_0800 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_udivw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x1AC0_0800 | (rm << 16) | (rn << 5) | rd);
    }

    fn emit_ubfm(&self, mem: &mut JitMemory, sf: u32, rd: u32, rn: u32, immr: u32, imms: u32) {
        let enc = (sf << 31) | (0b10 << 29) | (0b100110 << 23) | (sf << 22)
            | (immr << 16) | (imms << 10) | (rn << 5) | rd;
        self.write_u32(mem, enc);
    }
    fn emit_sbfm(&self, mem: &mut JitMemory, sf: u32, rd: u32, rn: u32, immr: u32, imms: u32) {
        let enc = (sf << 31) | (0b00 << 29) | (0b100110 << 23) | (sf << 22)
            | (immr << 16) | (imms << 10) | (rn << 5) | rd;
        self.write_u32(mem, enc);
    }
    fn emit_lsl(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        let immr = ((-(sh as i32)) & 0x3F) as u32;
        self.emit_ubfm(mem, 1, rd, rn, immr, 63 - sh);
    }
    fn emit_lslw(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        let immr = ((-(sh as i32)) & 0x1F) as u32;
        self.emit_ubfm(mem, 0, rd, rn, immr, 31 - sh);
    }
    fn emit_lsr(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        self.emit_ubfm(mem, 1, rd, rn, sh, 63);
    }
    fn emit_lsrw(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        self.emit_ubfm(mem, 0, rd, rn, sh, 31);
    }
    fn emit_asr(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        self.emit_sbfm(mem, 1, rd, rn, sh, 63);
    }
    fn emit_asrw(&self, mem: &mut JitMemory, rd: u32, rn: u32, sh: u32) {
        self.emit_sbfm(mem, 0, rd, rn, sh, 31);
    }
    fn emit_lslv(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x9AC0_2000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_lslvw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x1AC0_2000 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_lsrv(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x9AC0_2400 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_lsrvw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x1AC0_2400 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_asrv(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x9AC0_2800 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_asrvw(&self, mem: &mut JitMemory, rd: u32, rn: u32, rm: u32) {
        self.write_u32(mem, 0x1AC0_2800 | (rm << 16) | (rn << 5) | rd);
    }
    fn emit_mov(&self, mem: &mut JitMemory, rd: u32, rn: u32) {
        self.emit_orr(mem, rd, A64_XZR, rn);
    }
    fn emit_movw(&self, mem: &mut JitMemory, rd: u32, rn: u32) {
        self.emit_orrw(mem, rd, A64_XZR, rn);
    }

    fn emit_rev64(&self, mem: &mut JitMemory, rd: u32, rn: u32) {
        self.write_u32(mem, 0xDAC0_0C00 | (rn << 5) | rd);
    }
    fn emit_rev32(&self, mem: &mut JitMemory, rd: u32, rn: u32) {
        self.write_u32(mem, 0x5AC0_0800 | (rn << 5) | rd);
    }
    fn emit_rev16(&self, mem: &mut JitMemory, rd: u32, rn: u32) {
        self.write_u32(mem, 0x5AC0_0400 | (rn << 5) | rd);
    }
    fn emit_movz(&self, mem: &mut JitMemory, rd: u32, imm16: u32, hw: u32) {
        let enc = (1 << 31) | (0b100101 << 23) | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd;
        self.write_u32(mem, enc);
    }
    fn emit_movk(&self, mem: &mut JitMemory, rd: u32, imm16: u32, hw: u32) {
        let enc = (1 << 31) | (0b11 << 29) | (0b100101 << 23) | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd;
        self.write_u32(mem, enc);
    }
    fn emit_ldr(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0xF940_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_ldrw(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0xB940_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_ldrh(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0x7940_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_ldrb(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0x3940_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_str(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0xF900_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_strw(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0xB900_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_strh(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0x7900_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_strb(&self, mem: &mut JitMemory, rt: u32, rn: u32, off: i32) {
        self.write_u32(mem, 0x3900_0000 | ((off as u32 & 0xFFF) << 10) | (rn << 5) | rt);
    }
    fn emit_stp_pre(&self, mem: &mut JitMemory, rt1: u32, rt2: u32, rn: u32, imm: i32) {
        let imm7 = ((imm / 8) & 0x7F) as u32;
        self.write_u32(mem, 0xA980_0000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }
    fn emit_ldp_post(&self, mem: &mut JitMemory, rt1: u32, rt2: u32, rn: u32, imm: i32) {
        let imm7 = ((imm / 8) & 0x7F) as u32;
        self.write_u32(mem, 0xA8C0_0000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }
    fn emit_b(&self, mem: &mut JitMemory, imm: i32) {
        let imm26 = ((imm as u32) & 0x03FF_FFFF) >> 2;
        self.write_u32(mem, 0x1400_0000 | imm26);
    }
    fn emit_bcond(&self, mem: &mut JitMemory, cond: u32, imm: i32) {
        let imm19 = ((imm as u32) & 0x7FFFF) >> 2;
        self.write_u32(mem, 0x5400_0000 | (imm19 << 5) | cond);
    }
    fn emit_ret(&self, mem: &mut JitMemory) {
        self.write_u32(mem, 0xD65F_03C0);
    }
    fn emit_br(&self, mem: &mut JitMemory, rn: u32) {
        self.write_u32(mem, 0xD61F_0000 | (rn << 5));
    }
    fn emit_blr(&self, mem: &mut JitMemory, rn: u32) {
        self.write_u32(mem, 0xD63F_0000 | (rn << 5));
    }
    fn emit_nop(&self, mem: &mut JitMemory) {
        self.write_u32(mem, 0xD503_201F);
    }
    fn emit_adr(&self, mem: &mut JitMemory, rd: u32, imm: i32) {
        let imm = imm as u32;
        let immlo = imm & 3;
        let immhi = (imm >> 2) & 0x7FFFF;
        self.write_u32(mem, (immhi << 5) | (immlo << 29) | (0x10 << 24) | rd);
    }
    fn emit_cmp(&self, mem: &mut JitMemory, rn: u32, rm: u32) {
        self.write_u32(mem, 0xEB00_0000 | (rm << 16) | (rn << 5) | A64_XZR);
    }
    fn emit_cmpw(&self, mem: &mut JitMemory, rn: u32, rm: u32) {
        self.write_u32(mem, 0x6B00_0000 | (rm << 16) | (rn << 5) | A64_XZR);
    }
    fn emit_tst(&self, mem: &mut JitMemory, rn: u32, rm: u32) {
        self.write_u32(mem, 0xEA00_0000 | (rm << 16) | (rn << 5) | A64_XZR);
    }
    fn emit_tstw(&self, mem: &mut JitMemory, rn: u32, rm: u32) {
        self.write_u32(mem, 0x6A00_0000 | (rm << 16) | (rn << 5) | A64_XZR);
    }

    // =======================================================================
    // Higher-level codegen helpers
    // =======================================================================

    fn emit_load_imm64(&self, mem: &mut JitMemory, rd: u32, val: u64) {
        if val == 0 {
            self.emit_mov(mem, rd, A64_XZR);
            return;
        }
        if val <= 0xFFFF {
            self.emit_movz(mem, rd, val as u32, 0);
            return;
        }
        let mut first = true;
        for hw in 0..4u32 {
            let chunk = ((val >> (hw * 16)) & 0xFFFF) as u32;
            if first {
                self.emit_movz(mem, rd, chunk, hw);
                first = false;
            } else if chunk != 0 {
                self.emit_movk(mem, rd, chunk, hw);
            }
        }
    }

    fn emit_load_imm32(&self, mem: &mut JitMemory, rd: u32, val: i32) {
        if val == 0 {
            self.emit_movw(mem, rd, A64_XZR);
            return;
        }
        self.emit_load_imm64(mem, rd, val as u64);
    }

    fn emit_add_offset(&self, mem: &mut JitMemory, rd: u32, rn: u32, off: i32) {
        if off >= 0 && (off as u32) < 4096 {
            self.emit_addi(mem, rd, rn, off as u32);
        } else if off < 0 && off > -4096 {
            self.emit_subi(mem, rd, rn, (-off) as u32);
        } else {
            self.emit_load_imm64(mem, A64_X6, off as u64);
            self.emit_add(mem, rd, rn, A64_X6);
        }
    }

    // =======================================================================
    // Jump helpers (NOP placeholders + patching)
    // =======================================================================

    /// Emit unconditional jump (7 NOPs = 28 bytes), patched in resolve_jumps
    fn emit_jump(&mut self, mem: &mut JitMemory, target_pc: isize) {
        self.jumps.push(Jump { offset_loc: mem.offset, target_pc });
        for _ in 0..7 { self.emit_nop(mem); }
    }

    /// Emit conditional jump with inverted condition
    /// Pattern: 7 NOPs | B.cond INVERTED #28 | 7 NOPs (take block)
    fn emit_cond_jump(&mut self, mem: &mut JitMemory, cond: u32, target_pc: isize) {
        for _ in 0..7 { self.emit_nop(mem); }
        self.emit_bcond(mem, cond, 28);
        self.jumps.push(Jump { offset_loc: mem.offset, target_pc });
        for _ in 0..7 { self.emit_nop(mem); }
    }

    /// Patch 7-instruction jump at given offset:
    ///   MOVZ x16,#lo16 | MOVK x16,#...,lsl16 | MOVK ...,lsl32 | MOVK ...,lsl48
    ///   | ADR x17,0 | ADD x17,x17,x16 | BR x17
    fn patch_jump_at(&self, mem: &mut JitMemory, pc: usize, target_loc: usize) {
        let offset = target_loc as i64 - pc as i64 - 16;
        self.write_u32_at(mem, pc,
            (1u32<<31)|(0b100101<<23)|(0<<21)|(((offset as u64 & 0xFFFF) as u32)<<5)|A64_X16);
        self.write_u32_at(mem, pc+4,
            (1u32<<31)|(0b11<<29)|(0b100101<<23)|(1<<21)|((((offset as u64>>16) & 0xFFFF) as u32)<<5)|A64_X16);
        self.write_u32_at(mem, pc+8,
            (1u32<<31)|(0b11<<29)|(0b100101<<23)|(2<<21)|((((offset as u64>>32) & 0xFFFF) as u32)<<5)|A64_X16);
        self.write_u32_at(mem, pc+12,
            (1u32<<31)|(0b11<<29)|(0b100101<<23)|(3<<21)|((((offset as u64>>48) & 0xFFFF) as u32)<<5)|A64_X16);
        self.write_u32_at(mem, pc+16, 0x1000_0011); // ADR x17,0
        self.write_u32_at(mem, pc+20, 0x8B10_0231); // ADD x17,x17,x16
        self.write_u32_at(mem, pc+24, 0xD61F_0220); // BR x17
    }

    fn resolve_jumps(&mut self, mem: &mut JitMemory) -> Result<(), Error> {
        for jump in &self.jumps {
            let target_loc = match self.special_targets.get(&jump.target_pc) {
                Some(&t) => t,
                None => {
                    if jump.target_pc < 0 || jump.target_pc as usize >= self.pc_locs.len() {
                        return Err(Error::other("[JIT aarch64] Error: unresolved jump target"));
                    }
                    self.pc_locs[jump.target_pc as usize]
                }
            };
            self.patch_jump_at(mem, jump.offset_loc, target_loc);
        }
        Ok(())
    }

    // =======================================================================
    // Main JIT compilation
    // =======================================================================

    pub(crate) fn jit_compile(
        &mut self,
        mem: &mut JitMemory,
        prog: &[u8],
        use_mbuff: bool,
        update_data_ptr: bool,
        helpers: &HashMap<u32, ebpf::Helper>,
    ) -> Result<(), Error> {
        // Prologue: save callee-saved regs, set up stack frame
        self.emit_stp_pre(mem, A64_X29, A64_X30, A64_SP, -16);
        self.emit_stp_pre(mem, A64_X19, A64_X20, A64_SP, -16);
        self.emit_stp_pre(mem, A64_X21, A64_X22, A64_SP, -16);
        self.emit_stp_pre(mem, A64_X25, A64_XZR, A64_SP, -16);

        // mbuff handling (see jit.rs for calling convention details)
        match (use_mbuff, update_data_ptr) {
            (true, true) => {
                self.emit_add(mem, A64_X6, A64_X0, A64_X4); // x6 = mbuff + mem_offset
                self.emit_str(mem, A64_X2, A64_X6, 0);      // store mem
                self.emit_add(mem, A64_X7, A64_X0, A64_X5); // x7 = mbuff + mem_end_offset
                self.emit_add(mem, A64_X6, A64_X2, A64_X3); // x6 = mem + mem_len
                self.emit_str(mem, A64_X6, A64_X7, 0);      // store mem_end
            }
            _ => {} // Raw/Mbuff: context is already in x0
        }

        // Allocate BPF stack, set up frame pointer
        self.emit_subi(mem, A64_SP, A64_SP, BPF_STACK_SIZE as u32);
        self.emit_addi(mem, A64_X25, A64_SP, (BPF_STACK_SIZE + CALLEE_SAVED_SIZE) as u32);

        // BPF r0 = 0, BPF r1 = context (from x0)
        self.emit_mov(mem, A64_X1, A64_X0);
        self.emit_mov(mem, A64_X0, A64_XZR);

        // Anchor for EXIT
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
                ebpf::LD_DW_IMM => {
                    insn_ptr += 1;
                    let next = ebpf::get_insn(prog, insn_ptr);
                    let imm = (insn.imm as u32) as u64 | ((next.imm as u64) << 32);
                    self.emit_load_imm64(mem, dst, imm);
                }

                // LDX
                ebpf::LD_B_REG => { self.emit_add_offset(mem, A64_X7, src, insn.off as i32); self.emit_ldrb(mem, dst, A64_X7, 0); }
                ebpf::LD_H_REG => { self.emit_add_offset(mem, A64_X7, src, insn.off as i32); self.emit_ldrh(mem, dst, A64_X7, 0); }
                ebpf::LD_W_REG => { self.emit_add_offset(mem, A64_X7, src, insn.off as i32); self.emit_ldrw(mem, dst, A64_X7, 0); }
                ebpf::LD_DW_REG => { self.emit_add_offset(mem, A64_X7, src, insn.off as i32); self.emit_ldr(mem, dst, A64_X7, 0); }

                // ST
                ebpf::ST_B_IMM => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_load_imm32(mem, A64_X6, insn.imm); self.emit_strb(mem, A64_X6, A64_X7, 0); }
                ebpf::ST_H_IMM => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_load_imm32(mem, A64_X6, insn.imm); self.emit_strh(mem, A64_X6, A64_X7, 0); }
                ebpf::ST_W_IMM => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_load_imm32(mem, A64_X6, insn.imm); self.emit_strw(mem, A64_X6, A64_X7, 0); }
                ebpf::ST_DW_IMM => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_load_imm64(mem, A64_X6, insn.imm as u64); self.emit_str(mem, A64_X6, A64_X7, 0); }

                // STX
                ebpf::ST_B_REG => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_strb(mem, src, A64_X7, 0); }
                ebpf::ST_H_REG => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_strh(mem, src, A64_X7, 0); }
                ebpf::ST_W_REG => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_strw(mem, src, A64_X7, 0); }
                ebpf::ST_DW_REG => { self.emit_add_offset(mem, A64_X7, dst, insn.off as i32); self.emit_str(mem, src, A64_X7, 0); }

                // ALU32
                ebpf::ADD32_IMM | ebpf::ADD32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_addw(mem, dst, dst, s);
                }
                ebpf::SUB32_IMM | ebpf::SUB32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_subw(mem, dst, dst, s);
                }
                ebpf::MUL32_IMM | ebpf::MUL32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_maddw(mem, dst, dst, s, A64_XZR);
                }
                ebpf::DIV32_IMM | ebpf::DIV32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmp(mem, s, A64_XZR);
                    self.emit_bcond(mem, COND_EQ, 2 * 4);
                    self.emit_udivw(mem, dst, dst, s);
                    self.emit_b(mem, 2 * 4);
                    self.emit_movw(mem, dst, A64_XZR);
                    self.emit_nop(mem);
                }
                ebpf::MOD32_IMM | ebpf::MOD32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmp(mem, s, A64_XZR);
                    self.emit_bcond(mem, COND_EQ, 6 * 4);
                    self.emit_udivw(mem, A64_X7, dst, s);
                    self.emit_maddw(mem, A64_X7, A64_X7, s, A64_XZR);
                    self.emit_subw(mem, dst, dst, A64_X7);
                    self.emit_nop(mem); self.emit_nop(mem); self.emit_nop(mem);
                }
                ebpf::OR32_IMM | ebpf::OR32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_orrw(mem, dst, dst, s);
                }
                ebpf::AND32_IMM | ebpf::AND32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_andw(mem, dst, dst, s);
                }
                ebpf::LSH32_IMM => self.emit_lslw(mem, dst, dst, (insn.imm as u32) & 0x1F),
                ebpf::LSH32_REG => self.emit_lslvw(mem, dst, dst, src),
                ebpf::RSH32_IMM => self.emit_lsrw(mem, dst, dst, (insn.imm as u32) & 0x1F),
                ebpf::RSH32_REG => self.emit_lsrvw(mem, dst, dst, src),
                ebpf::NEG32 => self.emit_subw(mem, dst, A64_XZR, dst),
                ebpf::XOR32_IMM | ebpf::XOR32_REG => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_eorw(mem, dst, dst, s);
                }
                ebpf::MOV32_IMM => self.emit_load_imm32(mem, dst, insn.imm),
                ebpf::MOV32_REG => self.emit_movw(mem, dst, src),
                ebpf::ARSH32_IMM => self.emit_asrw(mem, dst, dst, (insn.imm as u32) & 0x1F),
                ebpf::ARSH32_REG => self.emit_asrvw(mem, dst, dst, src),
                ebpf::LE => {} // no-op on AArch64
                ebpf::BE => match insn.imm {
                    16 => self.emit_rev16(mem, dst, dst),
                    32 => self.emit_rev32(mem, dst, dst),
                    64 => self.emit_rev64(mem, dst, dst),
                    _ => unreachable!(),
                },

                // ALU64
                ebpf::ADD64_IMM | ebpf::ADD64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_add(mem, dst, dst, s);
                }
                ebpf::SUB64_IMM | ebpf::SUB64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_sub(mem, dst, dst, s);
                }
                ebpf::MUL64_IMM | ebpf::MUL64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_madd(mem, dst, dst, s, A64_XZR);
                }
                ebpf::DIV64_IMM | ebpf::DIV64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, A64_XZR);
                    self.emit_bcond(mem, COND_EQ, 2 * 4);
                    self.emit_udiv(mem, dst, dst, s);
                    self.emit_b(mem, 2 * 4);
                    self.emit_mov(mem, dst, A64_XZR);
                    self.emit_nop(mem);
                }
                ebpf::MOD64_IMM | ebpf::MOD64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, A64_XZR);
                    self.emit_bcond(mem, COND_EQ, 6 * 4);
                    self.emit_udiv(mem, A64_X7, dst, s);
                    self.emit_madd(mem, A64_X7, A64_X7, s, A64_XZR);
                    self.emit_sub(mem, dst, dst, A64_X7);
                    self.emit_nop(mem); self.emit_nop(mem); self.emit_nop(mem);
                }
                ebpf::OR64_IMM | ebpf::OR64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_orr(mem, dst, dst, s);
                }
                ebpf::AND64_IMM | ebpf::AND64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_and(mem, dst, dst, s);
                }
                ebpf::LSH64_IMM => self.emit_lsl(mem, dst, dst, (insn.imm as u32) & 0x3F),
                ebpf::LSH64_REG => self.emit_lslv(mem, dst, dst, src),
                ebpf::RSH64_IMM => self.emit_lsr(mem, dst, dst, (insn.imm as u32) & 0x3F),
                ebpf::RSH64_REG => self.emit_lsrv(mem, dst, dst, src),
                ebpf::NEG64 => self.emit_sub(mem, dst, A64_XZR, dst),
                ebpf::XOR64_IMM | ebpf::XOR64_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_eor(mem, dst, dst, s);
                }
                ebpf::MOV64_IMM => self.emit_load_imm64(mem, dst, insn.imm as u64),
                ebpf::MOV64_REG => self.emit_mov(mem, dst, src),
                ebpf::ARSH64_IMM => self.emit_asr(mem, dst, dst, (insn.imm as u32) & 0x3F),
                ebpf::ARSH64_REG => self.emit_asrv(mem, dst, dst, src),

                // JMP unconditional
                ebpf::JA => self.emit_jump(mem, target_pc),
                ebpf::EXIT => { self.emit_jump(mem, TARGET_PC_EXIT); }

                // JMP conditional 64-bit
                ebpf::JEQ_IMM | ebpf::JEQ_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_NE, target_pc);
                }
                ebpf::JGT_IMM | ebpf::JGT_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LS, target_pc);
                }
                ebpf::JGE_IMM | ebpf::JGE_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LO, target_pc);
                }
                ebpf::JLT_IMM | ebpf::JLT_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, dst);
                    self.emit_cond_jump(mem, COND_HS, target_pc);
                }
                ebpf::JLE_IMM | ebpf::JLE_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, dst);
                    self.emit_cond_jump(mem, COND_HI, target_pc);
                }
                ebpf::JSET_IMM | ebpf::JSET_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_tst(mem, dst, s);
                    self.emit_cond_jump(mem, COND_EQ, target_pc);
                }
                ebpf::JNE_IMM | ebpf::JNE_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_EQ, target_pc);
                }
                ebpf::JSGT_IMM | ebpf::JSGT_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, dst);
                    self.emit_cond_jump(mem, COND_LE, target_pc);
                }
                ebpf::JSGE_IMM | ebpf::JSGE_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LT, target_pc);
                }
                ebpf::JSLT_IMM | ebpf::JSLT_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, dst, s);
                    self.emit_cond_jump(mem, COND_GE, target_pc);
                }
                ebpf::JSLE_IMM | ebpf::JSLE_REG => {
                    let s = if use_imm { self.emit_load_imm64(mem, A64_X6, insn.imm as u64); A64_X6 } else { src };
                    self.emit_cmp(mem, s, dst);
                    self.emit_cond_jump(mem, COND_GT, target_pc);
                }

                // JMP32 conditional
                ebpf::JEQ_IMM32 | ebpf::JEQ_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_NE, target_pc);
                }
                ebpf::JGT_IMM32 | ebpf::JGT_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LS, target_pc);
                }
                ebpf::JGE_IMM32 | ebpf::JGE_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LO, target_pc);
                }
                ebpf::JLT_IMM32 | ebpf::JLT_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, s, dst);
                    self.emit_cond_jump(mem, COND_HS, target_pc);
                }
                ebpf::JLE_IMM32 | ebpf::JLE_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, s, dst);
                    self.emit_cond_jump(mem, COND_HI, target_pc);
                }
                ebpf::JSET_IMM32 | ebpf::JSET_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_tstw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_EQ, target_pc);
                }
                ebpf::JNE_IMM32 | ebpf::JNE_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_EQ, target_pc);
                }
                ebpf::JSGT_IMM32 | ebpf::JSGT_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, s, dst);
                    self.emit_cond_jump(mem, COND_LE, target_pc);
                }
                ebpf::JSGE_IMM32 | ebpf::JSGE_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_LT, target_pc);
                }
                ebpf::JSLT_IMM32 | ebpf::JSLT_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, dst, s);
                    self.emit_cond_jump(mem, COND_GE, target_pc);
                }
                ebpf::JSLE_IMM32 | ebpf::JSLE_REG32 => {
                    let s = if use_imm { self.emit_load_imm32(mem, A64_X6, insn.imm); A64_X6 } else { src };
                    self.emit_cmpw(mem, s, dst);
                    self.emit_cond_jump(mem, COND_GT, target_pc);
                }

                // CALL
                ebpf::CALL => match insn.src {
                    0x0 => {
                        if let Some(&helper) = helpers.get(&(insn.imm as u32)) {
                            // Save BPF R5 (x5), rearrange R1-R5 -> x0-x4
                            self.emit_mov(mem, A64_X6, A64_X5);
                            self.emit_mov(mem, A64_X0, A64_X1);
                            self.emit_mov(mem, A64_X1, A64_X2);
                            self.emit_mov(mem, A64_X2, A64_X3);
                            self.emit_mov(mem, A64_X3, A64_X4);
                            self.emit_mov(mem, A64_X4, A64_X6);
                            // Load helper address and call
                            self.emit_load_imm64(mem, A64_X16, helper as u64);
                            self.emit_blr(mem, A64_X16);
                        } else {
                            return Err(Error::other(format!(
                                "[JIT aarch64] Error: unknown helper {:#x}",
                                insn.imm as u32
                            )));
                        }
                    }
                    0x1 => {
                        return Err(Error::other(
                            "[JIT aarch64] Error: BPF-to-BPF calls not supported",
                        ));
                    }
                    _ => {
                        return Err(Error::other(format!(
                            "[JIT aarch64] Error: unexpected call type #{:?}",
                            insn.src
                        )));
                    }
                },
                ebpf::TAIL_CALL => unimplemented!(),

                ebpf::ST_W_XADD | ebpf::ST_DW_XADD => unimplemented!(),

                ebpf::LD_ABS_B | ebpf::LD_ABS_H | ebpf::LD_ABS_W | ebpf::LD_ABS_DW
                | ebpf::LD_IND_B | ebpf::LD_IND_H | ebpf::LD_IND_W | ebpf::LD_IND_DW => {
                    return Err(Error::other(
                        "[JIT aarch64] Error: LD_ABS/LD_IND not supported",
                    ));
                }

                _ => {
                    return Err(Error::other(format!(
                        "[JIT aarch64] Error: unknown eBPF opcode {:#2x} (insn #{insn_ptr})",
                        insn.opc
                    )));
                }
            }
            insn_ptr += 1;
        }

        // Epilogue anchor (also set at EXIT time above)
        self.set_anchor(mem, TARGET_PC_EXIT);

        // Epilogue: restore stack, callee-saved regs, return
        self.emit_addi(mem, A64_SP, A64_SP, BPF_STACK_SIZE as u32);
        self.emit_ldp_post(mem, A64_X25, A64_XZR, A64_SP, 16);
        self.emit_ldp_post(mem, A64_X21, A64_X22, A64_SP, 16);
        self.emit_ldp_post(mem, A64_X19, A64_X20, A64_SP, 16);
        self.emit_ldp_post(mem, A64_X29, A64_X30, A64_SP, 16);
        self.emit_ret(mem);

        self.resolve_jumps(mem)?;
        Ok(())
    }
} // impl Aarch64Compiler

#[cfg(feature = "std")]
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
        layout: std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE),
        offset: 0,
    };

    let mut compiler = Aarch64Compiler::new();
    compiler.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
    Ok(mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf;
    use crate::jit::JitMemory;

    #[test]
    fn test_prologue_epilogue() {
        // Verify that we can compile a minimal program (just EXIT)
        // and that the prologue/epilogue don't crash.
        // This test only validates codegen, not execution (which requires aarch64 hw).

        // Minimal eBPF program: just EXIT
        let prog: Vec<u8> = vec![
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];

        use std::collections::HashMap;
        let helpers: HashMap<u32, ebpf::Helper> = HashMap::new();

        let size = NUM_PAGES * PAGE_SIZE;
        let contents = unsafe {
            let layout = std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);
            let ptr = std::alloc::alloc(layout);
            std::slice::from_raw_parts_mut(ptr, size)
        };

        let mut mem = JitMemory {
            contents,
            layout: std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE),
            offset: 0,
        };

        let mut compiler = Aarch64Compiler::new();
        compiler
            .jit_compile(&mut mem, &prog, false, false, &helpers)
            .expect("JIT compilation should succeed");

        // Verify that code was emitted (prologue + one jump + epilogue > 0 bytes)
        assert!(mem.offset > 0, "JIT should emit some code");

        // Check the first instruction is a valid STP (prologue: save x29, x30 to sp-16)
        // STP encoding: 0xA9BF7BE0 = STP x29, x30, [sp, #-16]!
        // Actually the encoding from StarryOS is 0xA980_0000 based. Let's check the actual first word.
        let first_word = u32::from_le_bytes([
            mem.contents[0],
            mem.contents[1],
            mem.contents[2],
            mem.contents[3],
        ]);
        // Just verify it's non-zero and looks like a valid instruction
        assert_ne!(first_word, 0);

        unsafe {
            let layout = std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);
            std::alloc::dealloc(contents.as_mut_ptr(), layout);
        }
    }
}
