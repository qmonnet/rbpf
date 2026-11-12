// SPDX-License-Identifier: (Apache-2.0 OR MIT)
#![cfg(not(windows))]

use rbpf::{assembler::assemble, EbpfVmNoData, EbpfVmRaw};

#[cfg(not(feature = "std"))]
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

fn read_register_program(reg: u8) -> Vec<u8> {
    assemble(&format!("mov64 r0, r{reg}\nexit")).unwrap()
}

#[test]
fn jit_matches_interpreter_for_all_zero_initialized_value_registers() {
    // r0-r9 are zero in the interpreter's initial state when no packet memory
    // is supplied. r10 is intentionally excluded: it is the VM stack pointer,
    // whose value is specific to each execution instance.
    for reg in 0..=9 {
        let prog = read_register_program(reg);
        let interpreter_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
        let interpreter = interpreter_vm.execute_program().unwrap();

        let mut jit_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
        #[cfg(not(feature = "std"))]
        let mut exec_mem = alloc_exec_memory();
        #[cfg(not(feature = "std"))]
        jit_vm.set_jit_exec_memory(&mut exec_mem).unwrap();
        jit_vm.jit_compile().unwrap();
        let jit = unsafe { jit_vm.execute_program_jit().unwrap() };

        assert_eq!(interpreter, 0, "interpreter r{reg} initial state");
        assert_eq!(jit, interpreter, "JIT/interpreter mismatch for r{reg}");
    }
}

#[test]
fn jit_preserves_r1_packet_pointer_semantics() {
    let prog = assemble("mov64 r0, r1\nexit").unwrap();
    let mut mem = [0xabu8];

    let interpreter_vm = EbpfVmRaw::new(Some(&prog)).unwrap();
    let interpreter = interpreter_vm.execute_program(&mut mem).unwrap();

    let mut jit_vm = EbpfVmRaw::new(Some(&prog)).unwrap();
    #[cfg(not(feature = "std"))]
    let mut exec_mem = alloc_exec_memory();
    #[cfg(not(feature = "std"))]
    jit_vm.set_jit_exec_memory(&mut exec_mem).unwrap();
    jit_vm.jit_compile().unwrap();
    let jit = unsafe { jit_vm.execute_program_jit(&mut mem).unwrap() };

    assert_eq!(jit, interpreter);
    assert_eq!(jit, mem.as_ptr() as u64);
}

#[test]
fn original_regmap_case_now_matches() {
    #[rustfmt::skip]
    let prog = [
        0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let interpreter_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
    let interpreter = interpreter_vm.execute_program().unwrap();

    let mut jit_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
    #[cfg(not(feature = "std"))]
    let mut exec_mem = alloc_exec_memory();
    #[cfg(not(feature = "std"))]
    jit_vm.set_jit_exec_memory(&mut exec_mem).unwrap();
    jit_vm.jit_compile().unwrap();
    let jit = unsafe { jit_vm.execute_program_jit().unwrap() };

    assert_eq!(interpreter, 1);
    assert_eq!(jit, interpreter);
}

#[test]
fn mbuff_jit_preserves_pointer_initialization() {
    let prog = assemble("mov64 r0, r1\nexit").unwrap();
    let mut mem = [0xabu8];
    let mut mbuff = [0u8; 8];

    let interpreter_vm = rbpf::EbpfVmMbuff::new(Some(&prog)).unwrap();
    let interpreter = interpreter_vm
        .execute_program(&mut mem, &mut mbuff)
        .unwrap();

    let mut jit_vm = rbpf::EbpfVmMbuff::new(Some(&prog)).unwrap();
    #[cfg(not(feature = "std"))]
    let mut exec_mem = alloc_exec_memory();
    #[cfg(not(feature = "std"))]
    jit_vm.set_jit_exec_memory(&mut exec_mem).unwrap();
    jit_vm.jit_compile().unwrap();
    let jit = unsafe { jit_vm.execute_program_jit(&mut mem, &mut mbuff).unwrap() };

    assert_eq!(interpreter, mbuff.as_ptr() as u64);
    assert_eq!(jit, interpreter);
}
