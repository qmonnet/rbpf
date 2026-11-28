// SPDX-License-Identifier: (Apache-2.0 OR MIT)
extern crate rbpf;

use rbpf::ebpf::{self, Insn};

#[cfg(all(not(windows), not(feature = "std")))]
mod exec_memory;
#[cfg(all(not(windows), not(feature = "std")))]
use exec_memory::alloc_exec_memory;

#[cfg(not(windows))]
#[test]
fn test_jit_dry_run_resolves_jumps() {
    // Forward jump: dry-run sizing must walk resolve_jumps with write_enabled=false.
    let insns = [
        Insn { opc: ebpf::MOV32_IMM, dst: 0, src: 0, off: 0, imm: 1 },
        Insn { opc: ebpf::JA,         dst: 0, src: 0, off: 1, imm: 0 },
        Insn { opc: ebpf::MOV32_IMM, dst: 0, src: 0, off: 0, imm: 99 },
        Insn { opc: ebpf::EXIT,      dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 8];
    let mut vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem).unwrap(), 1);

    #[cfg(not(feature = "std"))]
    let mut exec_mem = alloc_exec_memory();
    #[cfg(not(feature = "std"))]
    vm.set_jit_exec_memory(&mut exec_mem).unwrap();
    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem).unwrap(), 1);
    }
}
