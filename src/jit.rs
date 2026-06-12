// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)

#![allow(clippy::single_match)]

#[cfg(not(feature = "std"))]
use crate::ErrorKind;
use crate::{Error, HashMap, ebpf};
use core::fmt::Error as FormatterError;
use core::fmt::Formatter;
use core::mem;
use core::ops::{Index, IndexMut};

#[cfg(target_arch = "aarch64")]
#[path = "jit_aarch64.rs"]
mod jit_aarch64;
#[cfg(target_arch = "riscv64")]
#[path = "jit_riscv64.rs"]
mod jit_riscv64;
#[cfg(target_arch = "x86_64")]
#[path = "jit_x86_64.rs"]
mod jit_x86_64;

type MachineCode = unsafe fn(*mut u8, usize, *mut u8, usize, usize, usize) -> u64;

const PAGE_SIZE: usize = 4096;

fn round_up_to_page(size: usize) -> usize {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// Special values for target_pc in struct Jump
const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;

pub struct JitMemory<'a> {
    contents: &'a mut [u8],
    write_enabled: bool,
    #[cfg(feature = "std")]
    layout: std::alloc::Layout,
    offset: usize,
}

impl<'a> JitMemory<'a> {
    fn counter() -> JitMemory<'a> {
        let contents: &'a mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::NonNull::<u8>::dangling().as_ptr(), 0)
        };
        JitMemory {
            contents,
            write_enabled: false,
            #[cfg(feature = "std")]
            layout: unsafe { std::alloc::Layout::from_size_align_unchecked(0, 1) },
            offset: 0,
        }
    }

    #[cfg(feature = "std")]
    pub fn new(
        prog: &[u8],
        helpers: &HashMap<u32, ebpf::Helper>,
        use_mbuff: bool,
        update_data_ptr: bool,
    ) -> Result<JitMemory<'a>, Error> {
        let layout;

        // Pass 1: size-only, no writes.
        let mut counter = JitMemory::counter();
        #[cfg(target_arch = "x86_64")]
        {
            let mut jit = jit_x86_64::JitCompiler::new();
            jit.jit_compile(&mut counter, prog, use_mbuff, update_data_ptr, helpers)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let mut jit = jit_riscv64::RiscV64Compiler::new();
            jit.jit_compile(&mut counter, prog, use_mbuff, update_data_ptr, helpers)?;
        }
        let size = round_up_to_page(counter.offset.max(PAGE_SIZE));

        let contents = unsafe {
            // Create a layout with the proper size and alignment.
            layout = std::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);

            // Allocate the region of memory.
            let ptr = std::alloc::alloc(layout);
            if ptr.is_null() {
                return Err(Error::from(std::io::ErrorKind::OutOfMemory));
            }

            // Protect it.
            libc::mprotect(ptr.cast(), size, libc::PROT_EXEC | libc::PROT_WRITE);

            // Convert to a slice.
            std::slice::from_raw_parts_mut(ptr, size)
        };
        let contents: &'a mut [u8] = unsafe { mem::transmute(contents) };

        let mut mem = JitMemory {
            contents,
            write_enabled: true,
            layout,
            offset: 0,
        };

        #[cfg(target_arch = "x86_64")]
        {
            let mut jit = jit_x86_64::JitCompiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let mut jit = jit_riscv64::RiscV64Compiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut jit = jit_aarch64::Aarch64Compiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }

        Ok(mem)
    }

    #[cfg(not(feature = "std"))]
    pub fn new(
        prog: &[u8],
        executable_memory: &'a mut [u8],
        helpers: &HashMap<u32, ebpf::Helper>,
        use_mbuff: bool,
        update_data_ptr: bool,
    ) -> Result<JitMemory<'a>, Error> {
        // Pass 1: compute required size.
        let mut counter = JitMemory::counter();
        #[cfg(target_arch = "x86_64")]
        {
            let mut jit = jit_x86_64::JitCompiler::new();
            jit.jit_compile(&mut counter, prog, use_mbuff, update_data_ptr, helpers)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let mut jit = jit_riscv64::RiscV64Compiler::new();
            jit.jit_compile(&mut counter, prog, use_mbuff, update_data_ptr, helpers)?;
        }
        let size = round_up_to_page(counter.offset.max(PAGE_SIZE));

        let contents = executable_memory;
        if contents.len() < size {
            return Err(Error::new(
                ErrorKind::Other,
                "Executable memory is too small",
            ));
        }
        if contents.as_ptr() as usize % PAGE_SIZE != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                "Executable memory is not aligned",
            ));
        }

        let mut mem = JitMemory {
            contents,
            write_enabled: true,
            offset: 0,
        };

        #[cfg(target_arch = "x86_64")]
        {
            let mut jit = jit_x86_64::JitCompiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let mut jit = jit_riscv64::RiscV64Compiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut jit = jit_aarch64::Aarch64Compiler::new();
            jit.jit_compile(&mut mem, prog, use_mbuff, update_data_ptr, helpers)?;
            jit.resolve_jumps(&mut mem)?;
        }

        Ok(mem)
    }

    pub fn get_prog(&self) -> MachineCode {
        unsafe { mem::transmute(self.contents.as_ptr()) }
    }
}

impl Index<usize> for JitMemory<'_> {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.contents[_index]
    }
}

impl IndexMut<usize> for JitMemory<'_> {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.contents[_index]
    }
}

#[cfg(feature = "std")]
impl Drop for JitMemory<'_> {
    fn drop(&mut self) {
        unsafe {
            if self.layout.size() > 0 {
                std::alloc::dealloc(self.contents.as_mut_ptr(), self.layout);
            }
        }
    }
}

impl core::fmt::Debug for JitMemory<'_> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT contents: [")?;
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT memory")
            .field("offset", &self.offset)
            .finish()
    }
}
