use rbpf::{assembler::assemble, EbpfVmNoData, EbpfVmRaw};

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
    jit_vm.jit_compile().unwrap();
    let jit = unsafe { jit_vm.execute_program_jit(&mut mem).unwrap() };

    assert_eq!(jit, interpreter);
    assert_eq!(jit, mem.as_ptr() as u64);
}

#[test]
fn original_regmap_case_now_matches() {
    let prog = [
        0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let interpreter_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
    let interpreter = interpreter_vm.execute_program().unwrap();

    let mut jit_vm = EbpfVmNoData::new(Some(&prog)).unwrap();
    jit_vm.jit_compile().unwrap();
    let jit = unsafe { jit_vm.execute_program_jit().unwrap() };

    assert_eq!(interpreter, 1);
    assert_eq!(jit, interpreter);
}
