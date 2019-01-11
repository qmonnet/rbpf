// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! Virtual machine and JIT compiler for eBPF programs.
#![doc(html_logo_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.png",
       html_favicon_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.ico")]

#![warn(missing_docs)]
// There are unused mut warnings due to unsafe code.
#![allow(unused_mut)]
// Allows old-style clippy
#![allow(renamed_and_removed_lints)]

#![cfg_attr(feature = "cargo-clippy", allow(redundant_field_names, single_match, cast_lossless, doc_markdown, match_same_arms, unreadable_literal, new_ret_no_self))]

extern crate byteorder;
extern crate combine;
extern crate time;

use std::u32;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use byteorder::{ByteOrder, LittleEndian};
use elf::EBpfElf;

pub mod assembler;
pub mod disassembler;
pub mod ebpf;
pub mod elf;
pub mod helpers;
pub mod insn_builder;
mod asm_parser;
#[cfg(not(windows))]
mod jit;
mod verifier;

/// eBPF verification function that returns an error if the program does not meet its requirements.
///
/// Some examples of things the verifier may reject the program for:
///
///   - Program does not terminate.
///   - Unknown instructions.
///   - Bad formed instruction.
///   - Unknown eBPF helper index.
pub type Verifier = fn(prog: &[u8]) -> Result<(), Error>;

/// eBPF Jit-compiled program.
pub type JitProgram = unsafe fn(*mut u8, usize, *mut u8, usize, usize, usize) -> u64;

/// One call frame
#[derive(Clone, Debug)]
struct CallFrame {
    stack:      Vec<u8>,
    return_ptr: usize,
}

/// Stack top and bottom addresses as integers
#[derive(Clone, Debug)]
struct StackPtrs {
    top: u64,
    bot: u64
}

/// When BPF calls a function other then a `helper` it expect the new
/// function to be called in its own frame.  CallFrames manages
/// call frames
struct CallFrames {
    current: usize,
    frames:        Vec<CallFrame>,
}
impl CallFrames {
    /// New call frame, depth indicates maximum call depth
    fn new(depth: usize, size: usize) -> Self {
        CallFrames {
            current: 0,
            frames:        vec![CallFrame { stack:      vec![0u8; size],
                                            return_ptr: 0
                                          };
                                depth]
        }
    }

    /// Get stack pointers
    fn get_stack(&self) -> StackPtrs {
        StackPtrs {
            top: self.frames[self.current].stack.as_ptr() as u64 +
                 self.frames[self.current].stack.len() as u64,
            bot: self.frames[self.current].stack.as_ptr() as u64
        }
    }

    /// Get current call frame index, 0 is the root frame
    #[allow(dead_code)]
    fn get_current_index(&self) -> usize {
        self.current
    }

    /// Push a frame
    fn push(&mut self, return_ptr: usize) -> Result<u64, Error> {
        self.current += 1;
        if self.current >= ebpf::MAX_CALL_DEPTH {
            self.current -= 1;
            Err(Error::new(ErrorKind::Other,
                           format!("Exceeded max BPF to BPF call depth of {:?}",
                                   ebpf::MAX_CALL_DEPTH)))?;
        }
        self.frames[self.current].return_ptr = return_ptr;
        Ok(self.frames[self.current].stack.as_ptr() as u64 +
           self.frames[self.current].stack.len() as u64)
    }

    /// Pop a frame
    fn pop(&mut self) -> Result<(u64, usize), Error> {
        if self.current == 0 {
            Err(Error::new(ErrorKind::Other, "Attempted to exit root call frame"))?;
        }
        let return_ptr =  self.frames[self.current].return_ptr;
        self.current -= 1;
        Ok((self.frames[self.current].stack.as_ptr() as u64 +
                self.frames[self.current].stack.len() as u64,
            return_ptr))
    }
}

// A metadata buffer with two offset indications. It can be used in one kind of eBPF VM to simulate
// the use of a metadata buffer each time the program is executed, without the user having to
// actually handle it. The offsets are used to tell the VM where in the buffer the pointers to
// packet data start and end should be stored each time the program is run on a new packet.
struct MetaBuff {
    data_offset:     usize,
    data_end_offset: usize,
    buffer:          Vec<u8>,
}

/// A virtual machine to run eBPF program. This kind of VM is used for programs expecting to work
/// on a metadata buffer containing pointers to packet data.
///
/// # Examples
///
/// ```
/// let prog = &[
///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff at offset 8 into R1.
///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Just for the example we create our metadata buffer from scratch, and we store the pointers
/// // to packet data start and end in it.
/// let mut mbuff = [0u8; 32];
/// unsafe {
///     let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
///     let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
///     *data     = mem.as_ptr() as u64;
///     *data_end = mem.as_ptr() as u64 + mem.len() as u64;
/// }
///
/// // Instantiate a VM.
/// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
///
/// // Provide both a reference to the packet data, and to the metadata buffer.
/// let res = vm.execute_program(mem, &mut mbuff).unwrap();
/// assert_eq!(res, 0x2211);
/// ```
pub struct EbpfVmMbuff<'a> {
    prog:            Option<&'a [u8]>,
    elf:             Option<EBpfElf>,
    verifier:        Verifier,
    jit:             Option<JitProgram>,
    helpers:         HashMap<u32, ebpf::Helper>,
    max_insn_count:  u64,
    last_insn_count: u64,
}

impl<'a> EbpfVmMbuff<'a> {

    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into R1.
    ///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// ```
    pub fn new(prog: Option<&'a [u8]>) -> Result<EbpfVmMbuff<'a>, Error> {
        if let Some(prog) = prog {
            verifier::check(prog)?;
        }

        Ok(EbpfVmMbuff {
            prog:            prog,
            elf:             None,
            verifier:        verifier::check,
            jit:             None,
            helpers:         HashMap::new(),
            max_insn_count:  0,
            last_insn_count: 0,
        })
    }

    /// Load a new eBPF program into the virtual machine instance.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let prog2 = &[
    ///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into R1.
    ///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog1)).unwrap();
    /// vm.set_program(prog2).unwrap();
    /// ```
    pub fn set_program(&mut self, prog: &'a [u8]) -> Result<(), Error> {
        (self.verifier)(prog)?;
        self.prog = Some(prog);
        Ok(())
    }

    /// Load a new eBPF program into the virtual machine instance.
    pub fn set_elf(&mut self, elf_bytes: &'a [u8]) -> Result<(), Error> {
        let elf = EBpfElf::load(elf_bytes)?;
        (self.verifier)(elf.get_text_bytes()?)?;
        self.elf = Some(elf);
        Ok(())
    }

    /// Set a new verifier function. The function should return an `Error` if the program should be
    /// rejected by the virtual machine. If a program has been loaded to the VM already, the
    /// verifier is immediately run.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// // Define a simple verifier function.
    /// fn verifier(prog: &[u8]) -> Result<(), Error> {
    ///     let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    ///     if last_insn.opc != ebpf::EXIT {
    ///         return Err(Error::new(ErrorKind::Other,
    ///                    "[Verifier] Error: program does not end with “EXIT” instruction"));
    ///     }
    ///     Ok(())
    /// }
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog1)).unwrap();
    /// // Change the verifier.
    /// vm.set_verifier(verifier).unwrap();
    /// ```
    pub fn set_verifier(&mut self, verifier: Verifier) -> Result<(), Error> {
        if let Some(ref elf) = self.elf {
            verifier(elf.get_text_bytes()?)?;
        } else if let Some(ref prog) = self.prog {
            verifier(prog)?;
        }
        self.verifier = verifier;
        Ok(())
    }

    /// Set a cap on the maximum number of instructions that a program may execute.
    /// If the maximum is set to zero, then no cap will be applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Set maximum instruction count.
    /// vm.set_max_instruction_count(1000).unwrap();
    /// ```
    pub fn set_max_instruction_count(&mut self, count: u64) -> Result<(), Error> {
        self.max_insn_count = count;
        Ok(())
    }

    /// Returns the number of instructions executed by the last program.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// 
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    /// 
    /// // Just for the example we create our metadata buffer from scratch, and we store the
    /// // pointers to packet data start and end in it.
    /// let mut mbuff = [0u8; 32];
    /// unsafe {
    ///     let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
    ///     let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
    ///     *data     = mem.as_ptr() as u64;
    ///     *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    /// }
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Execute the program.
    /// let res = vm.execute_program(mem, &mut mbuff).unwrap();
    /// // Get the number of instructions executed.
    /// let count = vm.get_last_instruction_count();
    /// ```
    pub fn get_last_instruction_count(&self) -> u64 {
        self.last_insn_count
    }

    /// Register a built-in or user-defined helper function in order to use it later from within
    /// the eBPF program. The helper is registered into a hashmap, so the `key` can be any `u32`.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::helpers;
    ///
    /// // This program was compiled with clang, from a C program containing the following single
    /// // instruction: `return bpf_trace_printk("foo %c %c %c\n", 10, 1, 2, 3);`
    /// let prog = &[
    ///     0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load 0 as u64 into r1 (That would be
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // replaced by tc by the address of
    ///                                                     // the format string, in the .map
    ///                                                     // section of the ELF file).
    ///     0xb7, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, // mov r2, 10
    ///     0xb7, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r3, 1
    ///     0xb7, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r4, 2
    ///     0xb7, 0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // mov r5, 3
    ///     0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // call helper with key 6
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    ///
    /// // Register a helper.
    /// // On running the program this helper will print the content of registers r3, r4 and r5 to
    /// // standard output.
    /// vm.register_helper(6, helpers::bpf_trace_printf).unwrap();
    /// ```
    pub fn register_helper(&mut self, key: u32, function: ebpf::HelperFunction) -> Result<(), Error> {
        self.helpers.insert(key, ebpf::Helper{ verifier: None, function });
        Ok(())
    }

    /// Register a user-defined helper function in order to use it later from within
    /// the eBPF program.  Normally helper functions are referred to by an index. (See helpers)
    /// but this function takes the name of the function.  The name is then hashed into a 32 bit
    /// number and used in the `call` instructions imm field.  If calling `set_elf` then
    /// the elf's relocations must reference this symbol using the same name.  This can usually be
    /// achieved by building the elf with unresolved symbols (think `extern foo(void)`).  If
    /// providing a program directly via `set_program` then any `call` instructions must already
    /// have the hash of the symbol name in its imm field.  To generate the correct hash of the
    /// symbol name use `ebpf::helpers::hash_symbol_name`.
    /// 
    /// Helper functions may treat their arguments as pointers, but there are safety issues
    /// in doing so.  To protect against bad pointer usage the VM will call the helper verifier
    /// function before calling the real helper.  The user-supplied helper verifier should be implemented
    /// so that it checks the usage of the pointers and returns an error if a problem is encountered.
    /// For example, if the helper function treats argument 1 as a pointer to a string then the 
    /// helper verification function must validate that argument 1 is indeed a valid pointer and
    /// that it is fully contained in one of the provided memory regions.
    /// 
    /// This function can be used along with jitted programs but be aware that unlike interpreted
    /// programs, jitted programs will not call the verification functions.  If you don't inherently
    /// trust the parameters being passed to helpers then jitted programs must only use helper's
    /// arguments as values.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    pub fn register_helper_ex(&mut self, name: &str, verifier: Option<ebpf::HelperVerifier>,
                              function: ebpf::HelperFunction) -> Result<(), Error> {
        self.helpers.insert(ebpf::hash_symbol_name(name.as_bytes()), ebpf::Helper{ verifier, function });
        Ok(())
    }

    /// Execute the program loaded, with the given packet data and metadata buffer.
    ///
    /// If the program is made to be compatible with Linux kernel, it is expected to load the
    /// address of the beginning and of the end of the memory area used for packet data from the
    /// metadata buffer, at some appointed offsets. It is up to the user to ensure that these
    /// pointers are correctly stored in the buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into R1.
    ///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Just for the example we create our metadata buffer from scratch, and we store the
    /// // pointers to packet data start and end in it.
    /// let mut mbuff = [0u8; 32];
    /// unsafe {
    ///     let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
    ///     let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
    ///     *data     = mem.as_ptr() as u64;
    ///     *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    /// }
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    ///
    /// // Provide both a reference to the packet data, and to the metadata buffer.
    /// let res = vm.execute_program(mem, &mut mbuff).unwrap();
    /// assert_eq!(res, 0x2211);
    /// ```
    #[allow(unknown_lints)]
    #[allow(cyclomatic_complexity)]
    pub fn execute_program(&mut self, mem: &[u8], mbuff: &[u8]) -> Result<u64, Error> {
        const U32MAX: u64 = u32::MAX as u64;

        let mut frames = CallFrames::new(ebpf::MAX_CALL_DEPTH, ebpf::STACK_SIZE);
        let mut ro_regions = Vec::new();
        let mut rw_regions = Vec::new();
        ro_regions.push(mbuff);
        rw_regions.push(mbuff);
        ro_regions.push(mem);
        rw_regions.push(mem);

        let mut entry: usize = 0;
        let prog =
        if let Some(ref elf) = self.elf {
            if let Ok(regions) = elf.get_rodata() {
                ro_regions.extend(regions);
            }
            entry = elf.get_entrypoint_instruction_offset()?;
            elf.get_text_bytes()?
        } else if let Some(ref prog) = self.prog {
            prog
        } else {
            Err(Error::new(ErrorKind::Other,
                           "Error: no program or elf set"))?
        };
        
        // R1 points to beginning of input memory, R10 to stack
        let mut reg: [u64;11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, frames.get_stack().top];

        if !mbuff.is_empty() {
            reg[1] = mbuff.as_ptr() as u64;
        }
        else if !mem.is_empty() {
            reg[1] = mem.as_ptr() as u64;
        }

        let check_mem_load = | addr: u64, len: usize, insn_ptr: usize, stack: &StackPtrs | {
            EbpfVmMbuff::check_mem(addr, len, "load", insn_ptr, stack, &ro_regions)
        };
        let check_mem_store = | addr: u64, len: usize, insn_ptr: usize, stack: &StackPtrs | {
            EbpfVmMbuff::check_mem(addr, len, "store", insn_ptr, stack, &rw_regions)
        };

        // Loop on instructions
        let mut insn_ptr: usize = entry;
        self.last_insn_count = 0;
        while insn_ptr * ebpf::INSN_SIZE < prog.len() {
            // println!("    BPF: frame {:?} insn {:4?} {}",
            //          frames.get_current_index(),
            //          insn_ptr, 
            //          disassembler::to_insn_vec(&prog[insn_ptr * ebpf::INSN_SIZE..])[0].desc);
            let insn = ebpf::get_insn(prog, insn_ptr);
            let _dst = insn.dst as usize;
            let _src = insn.src as usize;
            insn_ptr += 1;
            self.last_insn_count += 1;

            match insn.opc {

                // BPF_LD class
                // LD_ABS_* and LD_IND_* are supposed to load pointer to data from metadata buffer.
                // Since this pointer is constant, and since we already know it (mem), do not
                // bother re-fetching it, just use mem already.
                ebpf::LD_ABS_B   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u8;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_ABS_H   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u16;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_ABS_W   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u32;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_ABS_DW  => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + (insn.imm as u32) as u64) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_IND_B   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u8;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_IND_H   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u16;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_IND_W   => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u32;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_IND_DW  => reg[0] = unsafe {
                    let x = (mem.as_ptr() as u64 + reg[_src] + (insn.imm as u32) as u64) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },

                ebpf::LD_DW_IMM  => {
                    let next_insn = ebpf::get_insn(prog, insn_ptr);
                    insn_ptr += 1;
                    reg[_dst] = ((insn.imm as u32) as u64) + ((next_insn.imm as u64) << 32);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => reg[_dst] = unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u8;
                    check_mem_load(x as u64, 1, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_H_REG   => reg[_dst] = unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u16;
                    check_mem_load(x as u64, 2, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_W_REG   => reg[_dst] = unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u32;
                    check_mem_load(x as u64, 4, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },
                ebpf::LD_DW_REG  => reg[_dst] = unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_src] as *const u8).offset(insn.off as isize) as *const u64;
                    check_mem_load(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x as u64
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                    check_mem_store(x as u64, 1, insn_ptr, &frames.get_stack())?;
                    *x = insn.imm as u8;
                },
                ebpf::ST_H_IMM   => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                    check_mem_store(x as u64, 2, insn_ptr, &frames.get_stack())?;
                    *x = insn.imm as u16;
                },
                ebpf::ST_W_IMM   => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                    check_mem_store(x as u64, 4, insn_ptr, &frames.get_stack())?;
                    *x = insn.imm as u32;
                },
                ebpf::ST_DW_IMM  => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                    check_mem_store(x as u64, 8, insn_ptr, &frames.get_stack())?;
                    *x = insn.imm as u64;
                },

                // BPF_STX class
                ebpf::ST_B_REG   => unsafe {
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u8;
                    check_mem_store(x as u64, 1, insn_ptr, &frames.get_stack())?;
                    *x = reg[_src] as u8;
                },
                ebpf::ST_H_REG   => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u16;
                    check_mem_store(x as u64, 2, insn_ptr, &frames.get_stack())?;
                    *x = reg[_src] as u16;
                },
                ebpf::ST_W_REG   => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u32;
                    check_mem_store(x as u64, 4, insn_ptr, &frames.get_stack())?;
                    *x = reg[_src] as u32;
                },
                ebpf::ST_DW_REG  => unsafe {
                    #[allow(cast_ptr_alignment)]
                    let x = (reg[_dst] as *const u8).offset(insn.off as isize) as *mut u64;
                    check_mem_store(x as u64, 8, insn_ptr, &frames.get_stack())?;
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
                        Err(Error::new(ErrorKind::Other,"Error: division by 0"))?;
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
                        Err(Error::new(ErrorKind::Other,"Error: division by 0"))?;
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
                        Err(Error::new(ErrorKind::Other,"Error: division by 0"))?;
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
                        Err(Error::new(ErrorKind::Other,"Error: division by 0"))?;
                    }
                    reg[_dst] %= reg[_src];
                },
                ebpf::XOR64_IMM  => reg[_dst] ^= insn.imm  as u64,
                ebpf::XOR64_REG  => reg[_dst] ^= reg[_src],
                ebpf::MOV64_IMM  => reg[_dst] =  insn.imm  as u64,
                ebpf::MOV64_REG  => reg[_dst] =  reg[_src],
                ebpf::ARSH64_IMM => reg[_dst] = (reg[_dst] as i64 >> insn.imm)  as u64,
                ebpf::ARSH64_REG => reg[_dst] = (reg[_dst] as i64 >> reg[_src]) as u64,

                // BPF_JMP class
                // TODO: check this actually works as expected for signed / unsigned ops
                ebpf::JA         =>                                             insn_ptr = (insn_ptr as i16 + insn.off) as usize,
                ebpf::JEQ_IMM    => if  reg[_dst] == insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JEQ_REG    => if  reg[_dst] == reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGT_IMM    => if  reg[_dst] >  insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGT_REG    => if  reg[_dst] >  reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGE_IMM    => if  reg[_dst] >= insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JGE_REG    => if  reg[_dst] >= reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JLT_IMM    => if  reg[_dst] <  insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JLT_REG    => if  reg[_dst] <  reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JLE_IMM    => if  reg[_dst] <= insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JLE_REG    => if  reg[_dst] <= reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSET_IMM   => if  reg[_dst] &  insn.imm as u64 != 0     { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSET_REG   => if  reg[_dst] &  reg[_src]       != 0     { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JNE_IMM    => if  reg[_dst] != insn.imm as u64          { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JNE_REG    => if  reg[_dst] != reg[_src]                { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGT_IMM   => if  reg[_dst] as i64 >  insn.imm  as i64  { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGT_REG   => if  reg[_dst] as i64 >  reg[_src] as i64  { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGE_IMM   => if  reg[_dst] as i64 >= insn.imm  as i64  { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSGE_REG   => if  reg[_dst] as i64 >= reg[_src] as i64  { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSLT_IMM   => if (reg[_dst] as i64) <  insn.imm  as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSLT_REG   => if (reg[_dst] as i64) <  reg[_src] as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSLE_IMM   => if (reg[_dst] as i64) <= insn.imm  as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                ebpf::JSLE_REG   => if (reg[_dst] as i64) <= reg[_src] as i64 { insn_ptr = (insn_ptr as i16 + insn.off) as usize; },
                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL       => {
                    if let Some(helper) = self.helpers.get(&(insn.imm as u32)) {
                        if let Some(function) = helper.verifier {
                            function(reg[1], reg[2], reg[3], reg[4], reg[5], &ro_regions, &rw_regions)?;
                        }
                        reg[0] = (helper.function)(reg[1], reg[2], reg[3], reg[4], reg[5]);
                    } else if let Some(ref elf) = self.elf {
                        if let Some(new_insn_ptr) = elf.lookup_bpf_call(insn.imm as u32) {
                            // make BPF to BPF call
                            reg[ebpf::STACK_REG] = frames.push(insn_ptr)?;
                            insn_ptr = *new_insn_ptr;
                        } else {
                            elf.report_unresolved_symbol(insn_ptr - 1)?;
                        }
                    } else {
                        Err(Error::new(ErrorKind::Other,
                                       format!("Error: Unresolved symbol at instruction #{:?}", insn_ptr - 1)))?;
                    }
                },
                ebpf::EXIT       => {
                    match frames.pop() {
                        Ok((stack_top, ptr)) => {
                            // Return from BPF to BPF call
                            reg[ebpf::STACK_REG] = stack_top;
                            insn_ptr = ptr;
                        },
                        _        => return Ok(reg[0]),
                    }
                },
                ebpf::TAIL_CALL  => unimplemented!(),
                _                => unreachable!()
            }
            if (self.max_insn_count != 0) && (self.last_insn_count >= self.max_insn_count) {
                Err(Error::new(ErrorKind::Other, "Error: Execution exceeded maximum number of instructions allowed"))?;
            }
        }

        unreachable!()
    }

    fn check_mem(addr: u64, len: usize, access_type: &str, insn_ptr: usize, stack: &StackPtrs, regions: &'a [&[u8]]) -> Result<(), Error> {
        if stack.bot as u64 <= addr && addr + len as u64 <= stack.top {
            return Ok(());
        }
        
        for region in regions.iter() {
            if region.as_ptr() as u64 <= addr && addr + len as u64 <= region.as_ptr() as u64 + region.len() as u64 {
                return Ok(());
            }
        }
        
        let mut regions_string = "".to_string();
        if !regions.is_empty() {
            regions_string =  " regions".to_string();
            for region in regions.iter() {
                regions_string = format!("{} {:#x}/{:#x}", regions_string, region.as_ptr() as u64, region.len());
            }
        }

        Err(Error::new(ErrorKind::Other, format!(
            "Error: out of bounds memory {} (insn #{:?}), addr {:#x}/{:?} {}",
            access_type, insn_ptr - 1 , addr, len, regions_string
        )))
    }

    /// JIT-compile the loaded program. No argument required for this.
    ///
    /// If using helper functions, be sure to register them into the VM before calling this
    /// function.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into R1.
    ///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    ///
    /// vm.jit_compile();
    /// ```
    #[cfg(not(windows))]
    pub fn jit_compile(&mut self) -> Result<(), Error> {
        let prog =
        if let Some(ref elf) = self.elf {
            if elf.get_rodata().is_ok() {
                Err(Error::new(ErrorKind::Other,
                           "Error: JIT does not support RO data"))?
            }
            elf.get_text_bytes()?
        } else if let Some(ref prog) = self.prog {
            prog
        } else {
            Err(Error::new(ErrorKind::Other,
                           "Error: no program or elf set"))?
        };
        self.jit = Some(jit::compile(prog, &self.helpers, true, false)?);
        Ok(())
    }

    /// Execute the previously JIT-compiled program, with the given packet data and metadata
    /// buffer, in a manner very similar to `execute_program()`.
    ///
    /// If the program is made to be compatible with Linux kernel, it is expected to load the
    /// address of the beginning and of the end of the memory area used for packet data from the
    /// metadata buffer, at some appointed offsets. It is up to the user to ensure that these
    /// pointers are correctly stored in the buffer.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe, in particular there is no runtime
    /// check for memory access; so if the eBPF program attempts erroneous accesses, this may end
    /// very bad (program may segfault). It may be wise to check that the program works with the
    /// interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into r1.
    ///     0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Just for the example we create our metadata buffer from scratch, and we store the
    /// // pointers to packet data start and end in it.
    /// let mut mbuff = [0u8; 32];
    /// unsafe {
    ///     let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
    ///     let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
    ///     *data     = mem.as_ptr() as u64;
    ///     *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    /// }
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    ///
    /// // Provide both a reference to the packet data, and to the metadata buffer.
    /// # #[cfg(not(windows))]
    /// unsafe {
    ///     let res = vm.execute_program_jit(mem, &mut mbuff).unwrap();
    ///     assert_eq!(res, 0x2211);
    /// }
    /// ```
    pub unsafe fn execute_program_jit(&self, mem: &mut [u8], mbuff: &'a mut [u8]) -> Result<u64, Error> {
        // If packet data is empty, do not send the address of an empty slice; send a null pointer
        //  as first argument instead, as this is uBPF's behavior (empty packet should not happen
        //  in the kernel; anyway the verifier would prevent the use of uninitialized registers).
        //  See `mul_loop` test.
        let mem_ptr = match mem.len() {
            0 => std::ptr::null_mut(),
            _ => mem.as_ptr() as *mut u8
        };
        // The last two arguments are not used in this function. They would be used if there was a
        // need to indicate to the JIT at which offset in the mbuff mem_ptr and mem_ptr + mem.len()
        // should be stored; this is what happens with struct EbpfVmFixedMbuff.
        match self.jit {
            Some(jit) => Ok(jit(mbuff.as_ptr() as *mut u8, mbuff.len(), mem_ptr, mem.len(), 0, 0)),
            None => Err(Error::new(ErrorKind::Other,
                        "Error: program has not been JIT-compiled")),
        }
    }
}

/// A virtual machine to run eBPF program. This kind of VM is used for programs expecting to work
/// on a metadata buffer containing pointers to packet data, but it internally handles the buffer
/// so as to save the effort to manually handle the metadata buffer for the user.
///
/// This struct implements a static internal buffer that is passed to the program. The user has to
/// indicate the offset values at which the eBPF program expects to find the start and the end of
/// packet data in the buffer. On calling the `execute_program()` or `execute_program_jit()` functions, the
/// struct automatically updates the addresses in this static buffer, at the appointed offsets, for
/// the start and the end of the packet data the program is called upon.
///
/// # Examples
///
/// This was compiled with clang from the following program, in C:
///
/// ```c
/// #include <linux/bpf.h>
/// #include "path/to/linux/samples/bpf/bpf_helpers.h"
///
/// SEC(".classifier")
/// int classifier(struct __sk_buff *skb)
/// {
///   void *data = (void *)(long)skb->data;
///   void *data_end = (void *)(long)skb->data_end;
///
///   // Check program is long enough.
///   if (data + 5 > data_end)
///     return 0;
///
///   return *((char *)data + 5);
/// }
/// ```
///
/// Some small modifications have been brought to have it work, see comments.
///
/// ```
/// let prog = &[
///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
///     // Here opcode 0x61 had to be replace by 0x79 so as to load a 8-bytes long address.
///     // Also, offset 0x4c had to be replace with e.g. 0x40 so as to prevent the two pointers
///     // from overlapping in the buffer.
///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load pointer to mem from r1[0x40] to r2
///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
///     // Here opcode 0x61 had to be replace by 0x79 so as to load a 8-bytes long address.
///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load ptr to mem_end from r1[0x50] to r1
///     0x2d, 0x12, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
///     0x67, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, // r0 >>= 56
///     0xc7, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, // r0 <<= 56 (arsh) extend byte sign to u64
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem1 = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
/// let mem2 = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x27
/// ];
///
/// // Instantiate a VM. Note that we provide the start and end offsets for mem pointers.
/// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
///
/// // Provide only a reference to the packet data. We do not manage the metadata buffer.
/// let res = vm.execute_program(mem1).unwrap();
/// assert_eq!(res, 0xffffffffffffffdd);
///
/// let res = vm.execute_program(mem2).unwrap();
/// assert_eq!(res, 0x27);
/// ```
pub struct EbpfVmFixedMbuff<'a> {
    parent: EbpfVmMbuff<'a>,
    mbuff:  MetaBuff,
}

impl<'a> EbpfVmFixedMbuff<'a> {

    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
    ///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM. Note that we provide the start and end offsets for mem pointers.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    /// ```
    pub fn new(prog: Option<&'a [u8]>, data_offset: usize, data_end_offset: usize) -> Result<EbpfVmFixedMbuff<'a>, Error> {
        let parent = EbpfVmMbuff::new(prog)?;
        let get_buff_len = | x: usize, y: usize | if x >= y { x + 8 } else { y + 8 };
        let buffer = vec![0u8; get_buff_len(data_offset, data_end_offset)];
        let mbuff = MetaBuff {
            data_offset:     data_offset,
            data_end_offset: data_end_offset,
            buffer:          buffer,
        };
        Ok(EbpfVmFixedMbuff {
            parent: parent,
            mbuff:  mbuff,
        })
    }

    /// Load a new eBPF program into the virtual machine instance.
    ///
    /// At the same time, load new offsets for storing pointers to start and end of packet data in
    /// the internal metadata buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let prog2 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
    ///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x27,
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog1), 0, 0).unwrap();
    /// vm.set_program(prog2, 0x40, 0x50);
    ///
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 0x27);
    /// ```
    pub fn set_program(&mut self, prog: &'a [u8], data_offset: usize, data_end_offset: usize) -> Result<(), Error> {
        let get_buff_len = | x: usize, y: usize | if x >= y { x + 8 } else { y + 8 };
        let buffer = vec![0u8; get_buff_len(data_offset, data_end_offset)];
        self.mbuff.buffer = buffer;
        self.mbuff.data_offset = data_offset;
        self.mbuff.data_end_offset = data_end_offset;
        self.parent.set_program(prog)?;
        Ok(())
    }

    /// Set a new verifier function. The function should return an `Error` if the program should be
    /// rejected by the virtual machine. If a program has been loaded to the VM already, the
    /// verifier is immediately run.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// // Define a simple verifier function.
    /// fn verifier(prog: &[u8]) -> Result<(), Error> {
    ///     let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    ///     if last_insn.opc != ebpf::EXIT {
    ///         return Err(Error::new(ErrorKind::Other, 
    ///                    "[Verifier] Error: program does not end with “EXIT” instruction"));
    ///     }
    ///     Ok(())
    /// }
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog1)).unwrap();
    /// // Change the verifier.
    /// vm.set_verifier(verifier).unwrap();
    /// ```
    pub fn set_verifier(&mut self, verifier: Verifier) -> Result<(), Error> {
        self.parent.set_verifier(verifier)
    }

    /// Set a cap on the maximum number of instructions that a program may execute.
    /// If the maximum is set to zero, then no cap will be applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Set maximum instruction count.
    /// vm.set_max_instruction_count(1000).unwrap();
    /// ```
    pub fn set_max_instruction_count(&mut self, count: u64) -> Result<(), Error> {
        self.parent.set_max_instruction_count(count)
    }

    /// Returns the number of instructions executed by the last program.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// 
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x09,
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    /// // Execute the program.
    /// let res = vm.execute_program(mem).unwrap();
    /// // Get the number of instructions executed.
    /// let count = vm.get_last_instruction_count();
    /// ```
    pub fn get_last_instruction_count(&self) -> u64 {
        self.parent.get_last_instruction_count()
    }

    /// Register a built-in or user-defined helper function in order to use it later from within
    /// the eBPF program. The helper is registered into a hashmap, so the `key` can be any `u32`.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::helpers;
    ///
    /// // This program was compiled with clang, from a C program containing the following single
    /// // instruction: `return bpf_trace_printk("foo %c %c %c\n", 10, 1, 2, 3);`
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 6 instructions
    ///     0x71, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r1
    ///     0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r2, 0
    ///     0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r3, 0
    ///     0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r4, 0
    ///     0xb7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r5, 0
    ///     0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // call helper with key 1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x09,
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    ///
    /// // Register a helper. This helper will store the result of the square root of r1 into r0.
    /// vm.register_helper(1, helpers::sqrti);
    ///
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 3);
    /// ```
    pub fn register_helper(&mut self, key: u32, function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper(key, function)
    }

    /// Register a user-defined helper function in order to use it later from within
    /// the eBPF program.  Normally helper functions are referred to by an index. (See helpers)
    /// but this function takes the name of the function.  The name is then hashed into a 32 bit
    /// number and used in the `call` instructions imm field.  If calling `set_elf` then
    /// the elf's relocations must reference this symbol using the same name.  This can usually be
    /// achieved by building the elf with unresolved symbols (think `extern foo(void)`).  If
    /// providing a program directly via `set_program` then any `call` instructions must already
    /// have the hash of the symbol name in its imm field.  To generate the correct hash of the
    /// symbol name use `ebpf::helpers::hash_symbol_name`.
    /// 
    /// Helper functions may treat their arguments as pointers, but there are safety issues
    /// in doing so.  To protect against bad pointer usage the VM will call the helper verifier
    /// function before calling the real helper.  The user-supplied helper verifier should be implemented
    /// so that it checks the usage of the pointers and returns an error if a problem is encountered.
    /// For example, if the helper function treats argument 1 as a pointer to a string then the 
    /// helper verification function must validate that argument 1 is indeed a valid pointer and
    /// that it is fully contained in one of the provided memory regions.
    /// 
    /// This function can be used along with jitted programs but be aware that unlike interpreted
    /// programs, jitted programs will not call the verification functions.  If you don't inherently
    /// trust the parameters being passed to helpers then jitted programs must only use helper's
    /// arguments as values.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    pub fn register_helper_ex(&mut self, name: &str, verifier: Option<ebpf::HelperVerifier>,
                              function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper_ex(name, verifier, function)
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// If the program is made to be compatible with Linux kernel, it is expected to load the
    /// address of the beginning and of the end of the memory area used for packet data from some
    /// metadata buffer, which in the case of this VM is handled internally. The offsets at which
    /// the addresses should be placed should have be set at the creation of the VM.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
    ///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM. Note that we provide the start and end offsets for mem pointers.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    ///
    /// // Provide only a reference to the packet data. We do not manage the metadata buffer.
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 0xdd);
    /// ```
    pub fn execute_program(&mut self, mem: & mut [u8]) -> Result<u64, Error> {
        let l = self.mbuff.buffer.len();
        // Can this ever happen? Probably not, should be ensured at mbuff creation.
        if self.mbuff.data_offset + 8 > l || self.mbuff.data_end_offset + 8 > l {
            Err(Error::new(ErrorKind::Other, format!("Error: buffer too small ({:?}), cannot use data_offset {:?} and data_end_offset {:?}",
            l, self.mbuff.data_offset, self.mbuff.data_end_offset)))?;
        }
        LittleEndian::write_u64(&mut self.mbuff.buffer[(self.mbuff.data_offset) .. ], mem.as_ptr() as u64);
        LittleEndian::write_u64(&mut self.mbuff.buffer[(self.mbuff.data_end_offset) .. ], mem.as_ptr() as u64 + mem.len() as u64);
        self.parent.execute_program(mem, &self.mbuff.buffer)
    }

    /// JIT-compile the loaded program. No argument required for this.
    ///
    /// If using helper functions, be sure to register them into the VM before calling this
    /// function.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
    ///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM. Note that we provide the start and end offsets for mem pointers.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    ///
    /// vm.jit_compile();
    /// ```
    #[cfg(not(windows))]
    pub fn jit_compile(&mut self) -> Result<(), Error> {
        let prog =
            if let Some(ref elf) = self.parent.elf {
                if elf.get_rodata().is_ok() {
                    Err(Error::new(ErrorKind::Other,
                            "Error: JIT does not support RO data"))?
                }
                elf.get_text_bytes()?
            } else if let Some(ref prog) = self.parent.prog {
                prog
            } else {
                Err(Error::new(ErrorKind::Other,
                            "Error: no program or elf set"))?
            };
        self.parent.jit = Some(jit::compile(prog, &self.parent.helpers, true, true)?);
        Ok(())
    }

    /// Execute the previously JIT-compiled program, with the given packet data, in a manner very
    /// similar to `execute_program()`.
    ///
    /// If the program is made to be compatible with Linux kernel, it is expected to load the
    /// address of the beginning and of the end of the memory area used for packet data from some
    /// metadata buffer, which in the case of this VM is handled internally. The offsets at which
    /// the addresses should be placed should have be set at the creation of the VM.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe, in particular there is no runtime
    /// check for memory access; so if the eBPF program attempts erroneous accesses, this may end
    /// very bad (program may segfault). It may be wise to check that the program works with the
    /// interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x79, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem from r1[0x40] to r2
    ///     0x07, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // add r2, 5
    ///     0x79, 0x11, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // load mem_end from r1[0x50] to r1
    ///     0x2d, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // if r2 > r1 skip 3 instructions
    ///     0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load r2 (= *(mem + 5)) into r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM. Note that we provide the start and end offsets for mem pointers.
    /// let mut vm = solana_rbpf::EbpfVmFixedMbuff::new(Some(prog), 0x40, 0x50).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    ///
    /// // Provide only a reference to the packet data. We do not manage the metadata buffer.
    /// # #[cfg(not(windows))]
    /// unsafe {
    ///     let res = vm.execute_program_jit(mem).unwrap();
    ///     assert_eq!(res, 0xdd);
    /// }
    /// ```
    // This struct redefines the `execute_program_jit()` function, in order to pass the offsets
    // associated with the fixed mbuff.
    pub unsafe fn execute_program_jit(&mut self, mem: &'a mut [u8]) -> Result<u64, Error> {
        // If packet data is empty, do not send the address of an empty slice; send a null pointer
        //  as first argument instead, as this is uBPF's behavior (empty packet should not happen
        //  in the kernel; anyway the verifier would prevent the use of uninitialized registers).
        //  See `mul_loop` test.
        let mem_ptr = match mem.len() {
            0 => std::ptr::null_mut(),
            _ => mem.as_ptr() as *mut u8
        };
        
        match self.parent.jit {
            Some(jit) => Ok(jit(self.mbuff.buffer.as_ptr() as *mut u8,
                                self.mbuff.buffer.len(),
                                mem_ptr,
                                mem.len(), 
                                self.mbuff.data_offset,
                                self.mbuff.data_end_offset)),
            None => Err(Error::new(ErrorKind::Other,
                                   "Error: program has not been JIT-compiled"))
        }
    }
}

/// A virtual machine to run eBPF program. This kind of VM is used for programs expecting to work
/// directly on the memory area representing packet data.
///
/// # Examples
///
/// ```
/// let prog = &[
///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
///
/// // Provide only a reference to the packet data.
/// let res = vm.execute_program(mem).unwrap();
/// assert_eq!(res, 0x22cc);
/// ```
pub struct EbpfVmRaw<'a> {
    parent: EbpfVmMbuff<'a>,
}

impl<'a> EbpfVmRaw<'a> {

    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
    ///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
    ///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
    /// ```
    pub fn new(prog: Option<&'a [u8]>) -> Result<EbpfVmRaw<'a>, Error> {
        let parent = EbpfVmMbuff::new(prog)?;
         Ok(EbpfVmRaw {
            parent: parent,
        })
    }

    /// Load a new eBPF program into the virtual machine instance.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let prog2 = &[
    ///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
    ///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
    ///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x27,
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog1)).unwrap();
    /// vm.set_program(prog2);
    ///
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 0x22cc);
    /// ```
    pub fn set_program(&mut self, prog: &'a [u8]) -> Result<(), Error> {
        self.parent.set_program(prog)?;
        Ok(())
    }

    /// Load a new eBPF program into the virtual machine instance.
    pub fn set_elf(&mut self, elf: &'a [u8]) -> Result<(), Error> {
        self.parent.set_elf(elf)?;
        Ok(())
    }

    /// Set a new verifier function. The function should return an `Error` if the program should be
    /// rejected by the virtual machine. If a program has been loaded to the VM already, the
    /// verifier is immediately run.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// // Define a simple verifier function.
    /// fn verifier(prog: &[u8]) -> Result<(), Error> {
    ///     let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    ///     if last_insn.opc != ebpf::EXIT {
    ///         return Err(Error::new(ErrorKind::Other,
    ///                    "[Verifier] Error: program does not end with “EXIT” instruction"));
    ///     }
    ///     Ok(())
    /// }
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog1)).unwrap();
    /// // Change the verifier.
    /// vm.set_verifier(verifier).unwrap();
    /// ```
    pub fn set_verifier(&mut self, verifier: Verifier) -> Result<(), Error> {
        self.parent.set_verifier(verifier)
    }

    /// Set a cap on the maximum number of instructions that a program may execute.
    /// If the maximum is set to zero, then no cap will be applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Set maximum instruction count.
    /// vm.set_max_instruction_count(1000).unwrap();
    /// ```
    pub fn set_max_instruction_count(&mut self, count: u64) -> Result<(), Error> {
        self.parent.set_max_instruction_count(count)
    }

    /// Returns the number of instructions executed by the last program.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// 
    /// let mem = &mut [
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Execute the program.
    /// let res = vm.execute_program(mem, mem).unwrap();
    /// // Get the number of instructions executed.
    /// let count = vm.get_last_instruction_count();
    /// ```
    pub fn get_last_instruction_count(&self) -> u64 {
        self.parent.get_last_instruction_count()
    }

    /// Register a built-in or user-defined helper function in order to use it later from within
    /// the eBPF program. The helper is registered into a hashmap, so the `key` can be any `u32`.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::helpers;
    ///
    /// let prog = &[
    ///     0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxdw r1, r1[0x00]
    ///     0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r2, 0
    ///     0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r3, 0
    ///     0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r4, 0
    ///     0xb7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r5, 0
    ///     0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // call helper with key 1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
    ///
    /// // Register a helper. This helper will store the result of the square root of r1 into r0.
    /// vm.register_helper(1, helpers::sqrti);
    ///
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 0x10000000);
    /// ```
    pub fn register_helper(&mut self, key: u32, function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper(key, function)
    }

    /// Register a user-defined helper function in order to use it later from within
    /// the eBPF program.  Normally helper functions are referred to by an index. (See helpers)
    /// but this function takes the name of the function.  The name is then hashed into a 32 bit
    /// number and used in the `call` instructions imm field.  If calling `set_elf` then
    /// the elf's relocations must reference this symbol using the same name.  This can usually be
    /// achieved by building the elf with unresolved symbols (think `extern foo(void)`).  If
    /// providing a program directly via `set_program` then any `call` instructions must already
    /// have the hash of the symbol name in its imm field.  To generate the correct hash of the
    /// symbol name use `ebpf::helpers::hash_symbol_name`.
    /// 
    /// Helper functions may treat their arguments as pointers, but there are safety issues
    /// in doing so.  To protect against bad pointer usage the VM will call the helper verifier
    /// function before calling the real helper.  The user-supplied helper verifier should be implemented
    /// so that it checks the usage of the pointers and returns an error if a problem is encountered.
    /// For example, if the helper function treats argument 1 as a pointer to a string then the 
    /// helper verification function must validate that argument 1 is indeed a valid pointer and
    /// that it is fully contained in one of the provided memory regions.
    /// 
    /// This function can be used along with jitted programs but be aware that unlike interpreted
    /// programs, jitted programs will not call the verification functions.  If you don't inherently
    /// trust the parameters being passed to helpers then jitted programs must only use helper's
    /// arguments as values.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    pub fn register_helper_ex(&mut self, name: &str, verifier: Option<ebpf::HelperVerifier>,
                              function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper_ex(name, verifier, function)
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
    ///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
    ///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x27
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
    ///
    /// let res = vm.execute_program(mem).unwrap();
    /// assert_eq!(res, 0x22cc);
    /// ```
    pub fn execute_program(&mut self, mem: & mut [u8]) -> Result<u64, Error> {
        self.parent.execute_program(mem, &[])
    }

    /// JIT-compile the loaded program. No argument required for this.
    ///
    /// If using helper functions, be sure to register them into the VM before calling this
    /// function.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
    ///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
    ///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
    ///
    /// vm.jit_compile();
    /// ```
    #[cfg(not(windows))]
    pub fn jit_compile(&mut self) -> Result<(), Error> {
        let prog =
            if let Some(ref elf) = self.parent.elf {
                if elf.get_rodata().is_ok() {
                    Err(Error::new(ErrorKind::Other,
                            "Error: JIT does not support RO data"))?
                }
                elf.get_text_bytes()?
            } else if let Some(ref prog) = self.parent.prog {
                prog
            } else {
                Err(Error::new(ErrorKind::Other,
                            "Error: no program or elf set"))?
            };
        self.parent.jit = Some(jit::compile(prog, &self.parent.helpers, false, false)?);
        Ok(())
    }

    /// Execute the previously JIT-compiled program, with the given packet data, in a manner very
    /// similar to `execute_program()`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe, in particular there is no runtime
    /// check for memory access; so if the eBPF program attempts erroneous accesses, this may end
    /// very bad (program may segfault). It may be wise to check that the program works with the
    /// interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0x71, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r1[0x04], r1
    ///     0x07, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // add r1, 0x22
    ///     0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0x27
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmRaw::new(Some(prog)).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    ///
    /// # #[cfg(not(windows))]
    /// unsafe {
    ///     let res = vm.execute_program_jit(mem).unwrap();
    ///     assert_eq!(res, 0x22cc);
    /// }
    /// ```
    pub unsafe fn execute_program_jit(&self, mem: &mut [u8]) -> Result<u64, Error> {
        let mut mbuff = vec![];
        self.parent.execute_program_jit(mem, &mut mbuff)
    }
}

/// A virtual machine to run eBPF program. This kind of VM is used for programs that do not work
/// with any memory area—no metadata buffer, no packet data either.
///
/// # Examples
///
/// ```
/// let prog = &[
///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
///     0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r1, 1
///     0xb7, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r2, 2
///     0xb7, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // mov r3, 3
///     0xb7, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // mov r4, 4
///     0xb7, 0x05, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // mov r5, 5
///     0xb7, 0x06, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // mov r6, 6
///     0xb7, 0x07, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // mov r7, 7
///     0xb7, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // mov r8, 8
///     0x4f, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // or r0, r5
///     0x47, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, // or r0, 0xa0
///     0x57, 0x00, 0x00, 0x00, 0xa3, 0x00, 0x00, 0x00, // and r0, 0xa3
///     0xb7, 0x09, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, // mov r9, 0x91
///     0x5f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // and r0, r9
///     0x67, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // lsh r0, 32
///     0x67, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, // lsh r0, 22
///     0x6f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lsh r0, r8
///     0x77, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // rsh r0, 32
///     0x77, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, // rsh r0, 19
///     0x7f, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rsh r0, r7
///     0xa7, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // xor r0, 0x03
///     0xaf, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xor r0, r2
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
///
/// // Instantiate a VM.
/// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
///
/// // Provide only a reference to the packet data.
/// let res = vm.execute_program().unwrap();
/// assert_eq!(res, 0x11);
/// ```
pub struct EbpfVmNoData<'a> {
    parent: EbpfVmRaw<'a>,
}

impl<'a> EbpfVmNoData<'a> {

    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let vm = solana_rbpf::EbpfVmNoData::new(Some(prog));
    /// ```
    pub fn new(prog: Option<&'a [u8]>) -> Result<EbpfVmNoData<'a>, Error> {
        let parent = EbpfVmRaw::new(prog)?;
        Ok(EbpfVmNoData {
            parent: parent,
        })
    }

    /// Load a new eBPF program into the virtual machine instance.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let prog2 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog1)).unwrap();
    ///
    /// let res = vm.execute_program().unwrap();
    /// assert_eq!(res, 0x2211);
    ///
    /// vm.set_program(prog2);
    ///
    /// let res = vm.execute_program().unwrap();
    /// assert_eq!(res, 0x1122);
    /// ```
    pub fn set_program(&mut self, prog: &'a [u8]) -> Result<(), Error> {
        self.parent.set_program(prog)?;
        Ok(())
    }

    /// Load a new eBPF program into the virtual machine instance.
    pub fn set_elf(&mut self, elf: &'a [u8]) -> Result<(), Error> {
        self.parent.set_elf(elf)?;
        Ok(())
    }

    /// Set a new verifier function. The function should return an `Error` if the program should be
    /// rejected by the virtual machine. If a program has been loaded to the VM already, the
    /// verifier is immediately run.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// // Define a simple verifier function.
    /// fn verifier(prog: &[u8]) -> Result<(), Error> {
    ///     let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    ///     if last_insn.opc != ebpf::EXIT {
    ///         return Err(Error::new(ErrorKind::Other,
    ///                    "[Verifier] Error: program does not end with “EXIT” instruction"));
    ///     }
    ///     Ok(())
    /// }
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog1)).unwrap();
    /// // Change the verifier.
    /// vm.set_verifier(verifier).unwrap();
    /// ```
    pub fn set_verifier(&mut self, verifier: Verifier) -> Result<(), Error> {
        self.parent.set_verifier(verifier)
    }

    /// Set a cap on the maximum number of instructions that a program may execute.
    /// If the maximum is set to zero, then no cap will be applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
    /// // Set maximum instruction count.
    /// vm.set_max_instruction_count(1000).unwrap();
    /// ```
    pub fn set_max_instruction_count(&mut self, count: u64) -> Result<(), Error> {
        self.parent.set_max_instruction_count(count)
    }

    /// Returns the number of instruction executed by the last program.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Error, ErrorKind};
    /// use solana_rbpf::ebpf;
    ///
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    /// // Execute the program.
    /// let res = vm.execute_program().unwrap();
    /// // Get the number of instructions executed.
    /// let count = vm.get_last_instruction_count();
    /// ```
    pub fn get_last_instruction_count(&self) -> u64 {
        self.parent.get_last_instruction_count()
    }

    /// Register a built-in or user-defined helper function in order to use it later from within
    /// the eBPF program. The helper is registered into a hashmap, so the `key` can be any `u32`.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::helpers;
    ///
    /// let prog = &[
    ///     0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // mov r1, 0x010000000
    ///     0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r2, 0
    ///     0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r3, 0
    ///     0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r4, 0
    ///     0xb7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r5, 0
    ///     0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // call helper with key 1
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    ///
    /// // Register a helper. This helper will store the result of the square root of r1 into r0.
    /// vm.register_helper(1, helpers::sqrti).unwrap();
    ///
    /// let res = vm.execute_program().unwrap();
    /// assert_eq!(res, 0x1000);
    /// ```
    pub fn register_helper(&mut self, key: u32, function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper(key, function)
    }

    /// Register a user-defined helper function in order to use it later from within
    /// the eBPF program.  Normally helper functions are referred to by an index. (See helpers)
    /// but this function takes the name of the function.  The name is then hashed into a 32 bit
    /// number and used in the `call` instructions imm field.  If calling `set_elf` then
    /// the elf's relocations must reference this symbol using the same name.  This can usually be
    /// achieved by building the elf with unresolved symbols (think `extern foo(void)`).  If
    /// providing a program directly via `set_program` then any `call` instructions must already
    /// have the hash of the symbol name in its imm field.  To generate the correct hash of the
    /// symbol name use `ebpf::helpers::hash_symbol_name`.
    /// 
    /// Helper functions may treat their arguments as pointers, but there are safety issues
    /// in doing so.  To protect against bad pointer usage the VM will call the helper verifier
    /// function before calling the real helper.  The user-supplied helper verifier should be implemented
    /// so that it checks the usage of the pointers and returns an error if a problem is encountered.
    /// For example, if the helper function treats argument 1 as a pointer to a string then the 
    /// helper verification function must validate that argument 1 is indeed a valid pointer and
    /// that it is fully contained in one of the provided memory regions.
    /// 
    /// This function can be used along with jitted programs but be aware that unlike interpreted
    /// programs, jitted programs will not call the verification functions.  If you don't inherently
    /// trust the parameters being passed to helpers then jitted programs must only use helper's
    /// arguments as values.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all helpers before compiling the
    /// program. You should be able to change registered helpers after compiling, but not to add
    /// new ones (i.e. with new keys).
    pub fn register_helper_ex(&mut self, name: &str, verifier: Option<ebpf::HelperVerifier>,
                              function: ebpf::HelperFunction) -> Result<(), Error> {
        self.parent.register_helper_ex(name, verifier, function)
    }

    /// JIT-compile the loaded program. No argument required for this.
    ///
    /// If using helper functions, be sure to register them into the VM before calling this
    /// function.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    ///
    /// vm.jit_compile();
    /// ```
    #[cfg(not(windows))]
    pub fn jit_compile(&mut self) -> Result<(), Error> {
        self.parent.jit_compile()
    }

    /// Execute the program loaded, without providing pointers to any memory area whatsoever.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    ///
    /// // For this kind of VM, the `execute_program()` function needs no argument.
    /// let res = vm.execute_program().unwrap();
    /// assert_eq!(res, 0x1122);
    /// ```
    pub fn execute_program(&mut self) -> Result<(u64), Error> {
        self.parent.execute_program(&mut [])
    }

    /// Execute the previously JIT-compiled program, without providing pointers to any memory area
    /// whatsoever, in a manner very similar to `execute_program()`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe, in particular there is no runtime
    /// check for memory access; so if the eBPF program attempts erroneous accesses, this may end
    /// very bad (program may segfault). It may be wise to check that the program works with the
    /// interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    /// # Examples
    ///
    /// ```
    /// let prog = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, // mov r0, 0x2211
    ///     0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// let mut vm = solana_rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    ///
    /// # #[cfg(not(windows))]
    /// unsafe {
    ///     let res = vm.execute_program_jit().unwrap();
    ///     assert_eq!(res, 0x1122);
    /// }
    /// ```
    pub unsafe fn execute_program_jit(&self) -> Result<(u64), Error> {
        self.parent.execute_program_jit(&mut [])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frames() {
        const DEPTH: usize = 5;
        const SIZE: usize = 5;
        let mut frames = CallFrames::new(DEPTH, SIZE);
        let mut ptrs: Vec<StackPtrs> = Vec::new();
        for i in 0..DEPTH - 1 {
            println!("i: {:?}", i);
            assert_eq!(frames.get_current_index(), i);
            ptrs.push(frames.get_stack());
            assert_eq!(ptrs[i].top - ptrs[i].bot, SIZE as u64);
            println!("ptrs: {:?}", ptrs[i]);

            let top = frames.push(i).unwrap();
            let new_ptrs = frames.get_stack();
            assert_eq!(top, new_ptrs.top);
            assert_ne!(top, ptrs[i].top);
            assert_ne!(top, ptrs[i].bot);
            assert_ne!(ptrs[i].top, new_ptrs.top);
            assert_ne!(ptrs[i].top, new_ptrs.bot);
            assert_ne!(ptrs[i].bot, new_ptrs.top);
            assert_ne!(ptrs[i].bot, new_ptrs.bot);
        }
        println!("i: {:?}", DEPTH - 1);
        assert_eq!(frames.get_current_index(), DEPTH - 1);
        ptrs.push(frames.get_stack());
        assert_eq!(ptrs[DEPTH - 1].top - ptrs[DEPTH - 1].bot, SIZE as u64);
        println!("ptrs: {:?}", ptrs[DEPTH - 1]);

        assert!(frames.push(DEPTH - 1).is_err());

        for i in (0..DEPTH - 1).rev() {
            println!("i: {:?}", i);
            let (top, return_ptr) = frames.pop().unwrap();
            assert_eq!(ptrs[i].top, top);
            assert_eq!(i, return_ptr);
        }

        assert!(frames.pop().is_err());
    }

}
