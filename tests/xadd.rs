// SPDX-License-Identifier: (Apache-2.0 OR MIT)
extern crate rbpf;

use rbpf::ebpf::{self, Insn};

#[cfg(all(not(windows), not(feature = "std")))]
fn alloc_exec_memory() -> Box<[u8]> {
    let size = 4096;
    let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
    unsafe {
        let ptr = std::alloc::alloc(layout);
        assert!(!ptr.is_null(), "Failed to allocate memory");

        libc::mprotect(ptr.cast(), size, libc::PROT_EXEC | libc::PROT_WRITE);

        let slice = std::slice::from_raw_parts_mut(ptr, size);
        Box::from_raw(slice)
    }
}

#[test]
fn test_interpreter_xadd_w() {
    // r1 points to the provided memory buffer in EbpfVmRaw.
    // *(u32 *)(r1 + 0) += 5
    let insns = [
        Insn { opc: ebpf::MOV32_IMM, dst: 2, src: 0, off: 0, imm: 5 },
        Insn { opc: ebpf::ST_W_XADD, dst: 1, src: 2, off: 0, imm: 0 },
        Insn { opc: ebpf::LD_W_REG,  dst: 0, src: 1, off: 0, imm: 0 },
        Insn { opc: ebpf::EXIT,      dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 8];
    mem[..4].copy_from_slice(&10u32.to_le_bytes());

    let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem).unwrap(), 15);
}

#[test]
fn test_interpreter_xadd_w_unaligned() {
    // *(u32 *)(r1 + 1) is not naturally aligned.
    let insns = [
        Insn { opc: ebpf::MOV32_IMM, dst: 2, src: 0, off: 0, imm: 5 },
        Insn { opc: ebpf::ST_W_XADD, dst: 1, src: 2, off: 1, imm: 0 },
        Insn { opc: ebpf::EXIT,      dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 8];
    mem[1..5].copy_from_slice(&42u32.to_le_bytes());
    let initial = mem;

    let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    let result = vm.execute_program(&mut mem);
    assert!(result.is_err());
    assert_eq!(mem, initial);
    #[cfg(feature = "std")]
    assert!(result.unwrap_err().to_string().contains("unaligned atomic XADD"));
}

#[cfg(target_has_atomic = "64")]
#[test]
fn test_interpreter_xadd_dw_unaligned() {
    let insns = [
        Insn { opc: ebpf::MOV64_IMM,  dst: 2, src: 0, off: 0, imm: 7 },
        Insn { opc: ebpf::ST_DW_XADD, dst: 1, src: 2, off: 1, imm: 0 },
        Insn { opc: ebpf::EXIT,       dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 16];
    mem[1..9].copy_from_slice(&42u64.to_le_bytes());
    let initial = mem;

    let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    let result = vm.execute_program(&mut mem);
    assert!(result.is_err());
    assert_eq!(mem, initial);
    #[cfg(feature = "std")]
    assert!(result.unwrap_err().to_string().contains("unaligned atomic XADD"));
}

#[cfg(target_has_atomic = "64")]
#[test]
fn test_interpreter_xadd_dw() {
    // *(u64 *)(r1 + 0) += 7
    let insns = [
        Insn { opc: ebpf::MOV64_IMM,  dst: 2, src: 0, off: 0, imm: 7 },
        Insn { opc: ebpf::ST_DW_XADD, dst: 1, src: 2, off: 0, imm: 0 },
        Insn { opc: ebpf::LD_DW_REG,  dst: 0, src: 1, off: 0, imm: 0 },
        Insn { opc: ebpf::EXIT,       dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 16];
    mem[..8].copy_from_slice(&10u64.to_le_bytes());

    let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    assert_eq!(vm.execute_program(&mut mem).unwrap(), 17);
}

#[cfg(all(target_has_atomic = "64", target_arch = "x86_64", not(windows)))]
#[test]
fn test_jit_xadd_w_dw() {
    // Run both instructions through JIT as well (x86_64 only).
    let insns = [
        Insn { opc: ebpf::MOV32_IMM,  dst: 2, src: 0, off: 0, imm: 5 },
        Insn { opc: ebpf::ST_W_XADD,  dst: 1, src: 2, off: 0, imm: 0 },
        Insn { opc: ebpf::MOV64_IMM,  dst: 2, src: 0, off: 0, imm: 7 },
        Insn { opc: ebpf::ST_DW_XADD, dst: 1, src: 2, off: 8, imm: 0 },
        Insn { opc: ebpf::LD_DW_REG,  dst: 0, src: 1, off: 8, imm: 0 },
        Insn { opc: ebpf::EXIT,       dst: 0, src: 0, off: 0, imm: 0 },
    ];
    let prog = insns.iter().flat_map(|i| i.to_array()).collect::<Vec<u8>>();

    let mut mem = [0u8; 32];
    mem[..4].copy_from_slice(&10u32.to_le_bytes());
    mem[8..16].copy_from_slice(&10u64.to_le_bytes());

    let mut vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    #[cfg(all(not(windows), not(feature = "std")))]
    let mut exec_mem = alloc_exec_memory();
    #[cfg(all(not(windows), not(feature = "std")))]
    vm.set_jit_exec_memory(&mut exec_mem).unwrap();
    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem).unwrap(), 17);
    }
    assert_eq!(u32::from_le_bytes(mem[..4].try_into().unwrap()), 15);
}
