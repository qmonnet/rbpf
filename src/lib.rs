// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 Quentin Monnet <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


// One day we'll uncomment this!
// #![warn(missing_docs)]

use std::u32;
use std::collections::HashMap;

extern crate libc;

pub mod ebpf;
pub mod helpers;
mod verifier;
mod jit;

struct MetaBuff {
    data_offset:     usize,
    data_end_offset: usize,
    buffer:          std::vec::Vec<u8>,
}

struct EbpfVm<'a> {
    prog:    &'a std::vec::Vec<u8>,
    jit:     (fn (*mut u8, usize, *mut u8, usize, usize, usize) -> u64),
    helpers: HashMap<u32, fn (u64, u64, u64, u64, u64) -> u64>,
}

// Runs on packet + metadata buffer
impl<'a> EbpfVm<'a> {

    fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVm<'a> {
        verifier::check(prog);

        #[allow(unused_variables)]
        fn no_jit(foo: *mut u8, foo_len: usize, bar: *mut u8, bar_len: usize,
                  nodata_offset: usize, nodata_end_offset: usize) -> u64 {
            panic!("Error: program has not been JIT-compiled");
        }

        EbpfVm {
            prog:    prog,
            jit:     no_jit,
            helpers: HashMap::new(),
        }
    }

    fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>) {
        verifier::check(prog);
        self.prog = prog;
    }

    fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64) {
        self.helpers.insert(key, function);
    }

    fn prog_exec(&self, mem: &mut std::vec::Vec<u8>, mbuff: &'a mut MetaBuff) -> u64 {
        const U32MAX: u64 = u32::MAX as u64;

        let stack = vec![0u8;ebpf::STACK_SIZE];

        // R1 points to beginning of memory area, R10 to stack
        let mut reg: [u64;11] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, stack.as_ptr() as u64 + stack.len() as u64
        ];
        if mbuff.buffer.len() > 0 {
            reg[1] = mbuff.buffer.as_ptr() as u64;
        }
        else if mem.len() > 0 {
            reg[1] = mem.as_ptr() as u64;
        }

        let check_mem_load = | addr: u64, len: usize, insn_ptr: usize | {
            EbpfVm::check_mem(addr, len, "load", insn_ptr, &mbuff.buffer, &mem, &stack);
        };
        let check_mem_store = | addr: u64, len: usize, insn_ptr: usize | {
            EbpfVm::check_mem(addr, len, "store", insn_ptr, &mbuff.buffer, &mem, &stack);
        };

        // Loop on instructions
        let mut insn_ptr:usize = 0;
        while insn_ptr * ebpf::INSN_SIZE < self.prog.len() {
            let insn = ebpf::get_insn(self.prog, insn_ptr);
            insn_ptr += 1;
            // println!("R0: {:#x} R1: {:#x} R2: {:#x} R3: {:#x} R4: {:#x} R5: {:#x} R6: {:#x} R7: {:#x} R8: {:#x} R9: {:#x} R10: {:#x}",
            //          reg[0], reg[1], reg[2], reg[3], reg[4], reg[5], reg[6], reg[7], reg[8], reg[9], reg[10]);
            // println!("{:02x} {:x} {:x} {:04x} {:08x}", insn.opc, insn.dst, insn.src, insn.off, insn.imm);
            let _dst    = insn.dst as usize;
            let _src    = insn.src as usize;

            match insn.opc {

                // BPF_LD class
                ebpf::LD_ABS_B   => unimplemented!(),
                ebpf::LD_ABS_H   => unimplemented!(),
                ebpf::LD_ABS_W   => unimplemented!(),
                ebpf::LD_ABS_DW  => unimplemented!(),
                ebpf::LD_IND_B   => unimplemented!(),
                ebpf::LD_IND_H   => unimplemented!(),
                ebpf::LD_IND_W   => unimplemented!(),
                ebpf::LD_IND_DW  => unimplemented!(),

                // BPF_LDX class
                ebpf::LD_DW_IMM  => {
                    let next_insn = ebpf::get_insn(self.prog, insn_ptr);
                    insn_ptr += 1;
                    reg[_dst] = ((insn.imm as u32) as u64) + ((next_insn.imm as u64) << 32);
                },
                ebpf::LD_B_REG   => reg[_dst] = unsafe {
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u8;
                    check_mem_load(x as u64, 1, insn_ptr);
                    *x as u64
                },
                ebpf::LD_H_REG   => reg[_dst] = unsafe {
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u16;
                    check_mem_load(x as u64, 2, insn_ptr);
                    *x as u64
                },
                ebpf::LD_W_REG   => reg[_dst] = unsafe {
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u32;
                    check_mem_load(x as u64, 4, insn_ptr);
                    *x as u64
                },
                ebpf::LD_DW_REG  => reg[_dst] = unsafe {
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr);
                    *x as u64
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                    check_mem_store(x as u64, 1, insn_ptr);
                    *x = insn.imm as u8;
                },
                ebpf::ST_H_IMM   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                    check_mem_store(x as u64, 2, insn_ptr);
                    *x = insn.imm as u16;
                },
                ebpf::ST_W_IMM   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                    check_mem_store(x as u64, 4, insn_ptr);
                    *x = insn.imm as u32;
                },
                ebpf::ST_DW_IMM  => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                    check_mem_store(x as u64, 8, insn_ptr);
                    *x = insn.imm as u64;
                },

                // BPF_STX class
                ebpf::ST_B_REG   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                    check_mem_store(x as u64, 1, insn_ptr);
                    *x = reg[_src] as u8;
                },
                ebpf::ST_H_REG   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                    check_mem_store(x as u64, 2, insn_ptr);
                    *x = reg[_src] as u16;
                },
                ebpf::ST_W_REG   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                    check_mem_store(x as u64, 4, insn_ptr);
                    *x = reg[_src] as u32;
                },
                ebpf::ST_DW_REG  => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                    check_mem_store(x as u64, 8, insn_ptr);
                    *x = reg[_src] as u64;
                },
                ebpf::ST_W_XADD  => unimplemented!(),
                ebpf::ST_DW_XADD => unimplemented!(),

                // BPF_ALU class
                // TODO Check how overflow works in kernel. Should we &= U32MAX all src register value
                // before we do the operation?
                // Cf ((0x11 << 32) - (0x1 << 32)) as u32 VS ((0x11 << 32) as u32 - (0x1 << 32) as u32
                ebpf::ADD32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_add(insn.imm)         as u64, //((reg[_dst] & U32MAX) + insn.imm  as u64)     & U32MAX,
                ebpf::ADD32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_add(reg[_src] as i32) as u64, //((reg[_dst] & U32MAX) + (reg[_src] & U32MAX)) & U32MAX,
                ebpf::SUB32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(insn.imm)         as u64,
                ebpf::SUB32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(reg[_src] as i32) as u64,
                ebpf::MUL32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(insn.imm)         as u64,
                ebpf::MUL32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(reg[_src] as i32) as u64,
                ebpf::DIV32_IMM  => reg[_dst] = (reg[_dst] as u32 / insn.imm              as u32) as u64,
                ebpf::DIV32_REG  => {
                    if reg[_src] == 0 {
                        panic!("Error: division by 0");
                    }
                    reg[_dst] = (reg[_dst] as u32 / reg[_src] as u32) as u64;
                },
                ebpf::OR32_IMM   =>   reg[_dst] = (reg[_dst] as u32             | insn.imm  as u32) as u64,
                ebpf::OR32_REG   =>   reg[_dst] = (reg[_dst] as u32             | reg[_src] as u32) as u64,
                ebpf::AND32_IMM  =>   reg[_dst] = (reg[_dst] as u32             & insn.imm  as u32) as u64,
                ebpf::AND32_REG  =>   reg[_dst] = (reg[_dst] as u32             & reg[_src] as u32) as u64,
                ebpf::LSH32_IMM  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shl(insn.imm  as u32) as u64,
                ebpf::LSH32_REG  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shl(reg[_src] as u32) as u64,
                ebpf::RSH32_IMM  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shr(insn.imm  as u32) as u64,
                ebpf::RSH32_REG  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shr(reg[_src] as u32) as u64,
                ebpf::NEG32      => { reg[_dst] = (reg[_dst] as i32).wrapping_neg()                 as u64; reg[_dst] &= U32MAX; },
                ebpf::MOD32_IMM  =>   reg[_dst] = (reg[_dst] as u32             % insn.imm  as u32) as u64,
                ebpf::MOD32_REG  => {
                    if reg[_src] == 0 {
                        panic!("Error: division by 0");
                    }
                    reg[_dst] = (reg[_dst] as u32 % reg[_src] as u32) as u64;
                },
                ebpf::XOR32_IMM  =>   reg[_dst] = (reg[_dst] as u32             ^ insn.imm  as u32) as u64,
                ebpf::XOR32_REG  =>   reg[_dst] = (reg[_dst] as u32             ^ reg[_src] as u32) as u64,
                ebpf::MOV32_IMM  =>   reg[_dst] = insn.imm                                          as u64,
                ebpf::MOV32_REG  =>   reg[_dst] = (reg[_src] as u32)                                as u64,
                ebpf::ARSH32_IMM => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(insn.imm  as u32) as u64; reg[_dst] &= U32MAX; },
                ebpf::ARSH32_REG => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(reg[_src] as u32) as u64; reg[_dst] &= U32MAX; },
                ebpf::LE         => {
                    reg[_dst] = match insn.imm {
                        16 => (reg[_dst] as u16).to_le() as u64,
                        32 => (reg[_dst] as u32).to_le() as u64,
                        64 =>  reg[_dst].to_le(),
                        _  => unreachable!(),
                    };
                },
                ebpf::BE         => {
                    reg[_dst] = match insn.imm {
                        16 => (reg[_dst] as u16).to_be() as u64,
                        32 => (reg[_dst] as u32).to_be() as u64,
                        64 =>  reg[_dst].to_be(),
                        _  => unreachable!(),
                    };
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64),
                ebpf::ADD64_REG  => reg[_dst] = reg[_dst].wrapping_add(reg[_src]),
                ebpf::SUB64_IMM  => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64),
                ebpf::SUB64_REG  => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]),
                ebpf::MUL64_IMM  => reg[_dst] = reg[_dst].wrapping_mul(insn.imm as u64),
                ebpf::MUL64_REG  => reg[_dst] = reg[_dst].wrapping_mul(reg[_src]),
                ebpf::DIV64_IMM  => reg[_dst]                       /= insn.imm as u64,
                ebpf::DIV64_REG  => {
                    if reg[_src] == 0 {
                        panic!("Error: division by 0");
                    }
                    reg[_dst] /= reg[_src];
                },
                ebpf::OR64_IMM   => reg[_dst] |=  insn.imm as u64,
                ebpf::OR64_REG   => reg[_dst] |=  reg[_src],
                ebpf::AND64_IMM  => reg[_dst] &=  insn.imm as u64,
                ebpf::AND64_REG  => reg[_dst] &=  reg[_src],
                ebpf::LSH64_IMM  => reg[_dst] <<= insn.imm as u64,
                ebpf::LSH64_REG  => reg[_dst] <<= reg[_src],
                ebpf::RSH64_IMM  => reg[_dst] >>= insn.imm as u64,
                ebpf::RSH64_REG  => reg[_dst] >>= reg[_src],
                ebpf::NEG64      => reg[_dst] = -(reg[_dst] as i64) as u64,
                ebpf::MOD64_IMM  => reg[_dst] %=  insn.imm as u64,
                ebpf::MOD64_REG  => {
                    if reg[_src] == 0 {
                        panic!("Error: division by 0");
                    }
                    reg[_dst] %= reg[_src];
                },
                ebpf::XOR64_IMM  => reg[_dst] ^= insn.imm  as u64,
                ebpf::XOR64_REG  => reg[_dst] ^= reg[_src],
                ebpf::MOV64_IMM  => reg[_dst] =  insn.imm  as u64,
                ebpf::MOV64_REG  => reg[_dst] =  reg[_src],
                ebpf::ARSH64_IMM => reg[_dst] = (reg[_dst] as i64 >> insn.imm as u64) as u64,
                ebpf::ARSH64_REG => reg[_dst] = (reg[_dst] as i64 >> reg[_src])       as u64,

                // BPF_JMP class
                // TODO: check this actually works as expected for signed / unsigned ops
                ebpf::JA         =>                                           insn_ptr = (insn_ptr as i16 + insn.off) as usize,
                ebpf::JEQ_IMM    => if reg[_dst] == insn.imm as u64         { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JEQ_REG    => if reg[_dst] == reg[_src]               { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGT_IMM    => if reg[_dst] >  insn.imm as u64         { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGT_REG    => if reg[_dst] >  reg[_src]               { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGE_IMM    => if reg[_dst] >= insn.imm as u64         { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGE_REG    => if reg[_dst] >= reg[_src]               { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSET_IMM   => if reg[_dst] &  insn.imm as u64 != 0    { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSET_REG   => if reg[_dst] &  reg[_src]       != 0    { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JNE_IMM    => if reg[_dst] != insn.imm as u64         { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JNE_REG    => if reg[_dst] != reg[_src]               { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGT_IMM   => if reg[_dst] as i64 >  insn.imm  as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGT_REG   => if reg[_dst] as i64 >  reg[_src] as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGE_IMM   => if reg[_dst] as i64 >= insn.imm  as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGE_REG   => if reg[_dst] as i64 >= reg[_src] as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL       => if let Some(function) = self.helpers.get(&(insn.imm as u32)) {
                    reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                } else {
                    panic!("Error: unknown helper function (id: {:#x})", insn.imm as u32);
                },
                ebpf::TAIL_CALL  => unimplemented!(),
                ebpf::EXIT       => return reg[0],

                _                => unreachable!()
            }
        }

        return 0;
    }

    fn check_mem(addr: u64, len: usize, access_type: &str, insn_ptr: usize,
                 mbuff: &std::vec::Vec<u8>, mem: &std::vec::Vec<u8>, stack: &std::vec::Vec<u8>) {
        // WARNING: untested
        if mbuff.as_ptr() as u64 <= addr && addr + len as u64 <= mbuff.as_ptr() as u64 + mbuff.len() as u64 {
            return
        }
        if mem.as_ptr() as u64 <= addr && addr + len as u64 <= mem.as_ptr() as u64 + mem.len() as u64 {
            return
        }
        if stack.as_ptr() as u64 <= addr && addr + len as u64 <= stack.as_ptr() as u64 + stack.len() as u64 {
            return
        }

        panic!(
            "Error: out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\nmbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}",
            access_type, insn_ptr, addr, len,
            mbuff.as_ptr() as u64, mbuff.len(),
            mem.as_ptr() as u64, mem.len(),
            stack.as_ptr() as u64, stack.len()
        );
    }

    // Not used by “child” structs. Make it a trait?
    // fn jit_compile(&mut self) {
    // }

    fn prog_exec_jit(&self, mem: &mut std::vec::Vec<u8>, mbuff: &'a mut MetaBuff) -> u64 {
        // If packet data is empty, do not send the address of an empty vector; send a null
        // pointer (zero value) as first argument instead, as this is uBPF's behavior (empty
        // packet should not happen in the kernel; anyway the verifier would prevent the use of
        // uninitialized registers). See `mul_loop` test.
        let mem_ptr = match mem.len() {
            0 => 0 as *mut u8,
            _ => mem.as_ptr() as *mut u8
        };
        (self.jit)(mbuff.buffer.as_ptr() as *mut u8, mbuff.buffer.len(), mem_ptr, mem.len(),
                   mbuff.data_offset, mbuff.data_end_offset)
    }
}

// Runs on packet data, with a metadata buffer
pub struct EbpfVmMbuff<'a> {
    parent: EbpfVm<'a>,
}

impl<'a> EbpfVmMbuff<'a> {

    pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmMbuff<'a> {
        let parent = EbpfVm::new(prog);
        EbpfVmMbuff {
            parent: parent,
        }
    }

    pub fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>) {
        self.parent.set_prog(prog)
    }

    pub fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64) {
        self.parent.register_helper(key, function);
    }

    pub fn prog_exec(&self, mem: &'a mut std::vec::Vec<u8>, metadata: std::vec::Vec<u8>) -> u64 {
        let mut mbuff = MetaBuff {
            data_offset:     0,
            data_end_offset: 0,
            buffer:          metadata,
        };
        self.parent.prog_exec(mem, &mut mbuff)
    }

    pub fn jit_compile(&mut self) {
        self.parent.jit = jit::compile(&self.parent.prog, &self.parent.helpers, true, false);
    }

    pub fn prog_exec_jit(&self, mem: &'a mut std::vec::Vec<u8>, metadata: std::vec::Vec<u8>) -> u64 {
        let mut mbuff = MetaBuff {
            data_offset:     0,
            data_end_offset: 0,
            buffer:          metadata,
        };
        self.parent.prog_exec_jit(mem, &mut mbuff)
    }
}

// Runs on packet data, simulates a metadata buffer
pub struct EbpfVmFixedMbuff<'a> {
    parent: EbpfVm<'a>,
    mbuff:  MetaBuff,
}

impl<'a> EbpfVmFixedMbuff<'a> {

    pub fn new(prog: &'a std::vec::Vec<u8>, data_offset: usize, data_end_offset: usize) -> EbpfVmFixedMbuff<'a> {
        let parent = EbpfVm::new(prog);
        let get_buff_len = | x: usize, y: usize | if x >= y { x + 8 } else { y + 8 };
        let buffer = vec![0u8; get_buff_len(data_offset, data_end_offset)];
        let mbuff = MetaBuff {
            data_offset:     data_offset,
            data_end_offset: data_end_offset,
            buffer:          buffer,
        };
        EbpfVmFixedMbuff {
            parent: parent,
            mbuff:  mbuff,
        }
    }

    pub fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>) {
        self.parent.set_prog(prog)
    }

    pub fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64) {
        self.parent.register_helper(key, function);
    }

    pub fn prog_exec(&mut self, mem: &'a mut std::vec::Vec<u8>) -> u64 {
        let l = self.mbuff.buffer.len();
        // Can this happen? Yes, since MetaBuff is public.
        if self.mbuff.data_offset + 8 > l || self.mbuff.data_end_offset + 8 > l {
            panic!("Error: buffer too small ({:?}), cannot use data_offset {:?} and data_end_offset {:?}",
            l, self.mbuff.data_offset, self.mbuff.data_end_offset);
        }
        unsafe {
            let mut data     = self.mbuff.buffer.as_ptr().offset(self.mbuff.data_offset as isize)     as *mut u64;
            let mut data_end = self.mbuff.buffer.as_ptr().offset(self.mbuff.data_end_offset as isize) as *mut u64;
            *data     = mem.as_ptr() as u64;
            *data_end = mem.as_ptr() as u64 + mem.len() as u64;
        }
        self.parent.prog_exec(mem, &mut self.mbuff)
    }

    pub fn jit_compile(&mut self) {
        self.parent.jit = jit::compile(&self.parent.prog, &self.parent.helpers, true, true);
    }

    pub fn prog_exec_jit(&mut self, mem: &'a mut std::vec::Vec<u8>) -> u64 {
        self.parent.prog_exec_jit(mem, &mut self.mbuff)
    }
}

// Runs on a packet, no metadata buffer
pub struct EbpfVmRaw<'a> {
    parent: EbpfVm<'a>,
}

impl<'a> EbpfVmRaw<'a> {

    pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmRaw<'a> {
        let parent = EbpfVm::new(prog);
        EbpfVmRaw {
            parent: parent,
        }
    }

    pub fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>) {
        self.parent.set_prog(prog)
    }

    pub fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64) {
        self.parent.register_helper(key, function);
    }

    pub fn prog_exec(&self, mem: &'a mut std::vec::Vec<u8>) -> u64 {
        let mut mbuff = MetaBuff {
            data_offset:     0,
            data_end_offset: 0,
            buffer:          vec![]
        };
        self.parent.prog_exec(mem, &mut mbuff)
    }

    pub fn jit_compile(&mut self) {
        self.parent.jit = jit::compile(&self.parent.prog, &self.parent.helpers, false, false);
    }

    pub fn prog_exec_jit(&self, mem: &'a mut std::vec::Vec<u8>) -> u64 {
        let mut mbuff = MetaBuff {
            data_offset:     0,
            data_end_offset: 0,
            buffer:          vec![]
        };
        //println!("{:?}", &mbuff.buffer);
        //println!("{:?}", &mem);
        //println!("{:?}", mem.as_ptr() as *const u64);
        self.parent.prog_exec_jit(mem, &mut mbuff)
    }
}

// Runs without data -- no packet, no metadata buffer
pub struct EbpfVmNoData<'a> {
    parent: EbpfVmRaw<'a>,
}

impl<'a> EbpfVmNoData<'a> {

    pub fn new(prog: &'a std::vec::Vec<u8>) -> EbpfVmNoData<'a> {
        let parent = EbpfVmRaw::new(prog);
        EbpfVmNoData {
            parent: parent,
        }
    }

    pub fn set_prog(&mut self, prog: &'a std::vec::Vec<u8>) {
        self.parent.set_prog(prog)
    }

    pub fn register_helper(&mut self, key: u32, function: fn (u64, u64, u64, u64, u64) -> u64) {
        self.parent.register_helper(key, function);
    }

    pub fn jit_compile(&mut self) {
        self.parent.jit_compile();
    }

    pub fn prog_exec(&self) -> u64 {
        self.parent.prog_exec(&mut vec![])
    }

    pub fn prog_exec_jit(&self) -> u64 {
        self.parent.prog_exec_jit(&mut vec![])
    }
}
