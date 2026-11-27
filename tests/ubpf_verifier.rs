// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Converted from the tests for uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>

// The tests contained in this file are extracted from the unit tests of uBPF software. Each test
// in this file has a name in the form `test_verifier_<name>`, and corresponds to the
// (human-readable) code in `ubpf/tree/master/tests/<name>`, available at
// <https://github.com/iovisor/ubpf/tree/master/tests> (hyphen had to be replaced with underscores
// as Rust will not accept them in function names). It is strongly advised to refer to the uBPF
// version to understand what these program do.
//
// Each program was assembled from the uBPF version with the assembler provided by uBPF itself, and
// available at <https://github.com/iovisor/ubpf/tree/master/ubpf>.
// The very few modifications that have been realized should be indicated.

// These are unit tests for the eBPF “verifier”.

extern crate rbpf;

use rbpf::assembler::assemble;
use rbpf::ebpf;

#[test]
#[should_panic(expected = "[Verifier] Error: unsupported argument for LE/BE (insn #0)")]
fn test_verifier_err_endian_size() {
    let prog = &[
        0xdc, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // be3 r1 (invalid size)
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r1, 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();
}

// As in the Linux kernel, the verifier rejects legacy packet loads using reserved fields: 64-bit
// size, non-zero dst or offset fields, or a source register for LD_ABS.
#[test]
fn test_verifier_err_ld_abs_ind_reserved_fields() {
    for insn in [
        [0x38, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00], // ldabsdw 3 (unsupported size)
        [0x58, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00], // ldinddw r1, 3 (unsupported size)
        [0x30, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00], // ldabsb 3, dst=3 (reserved field)
        [0x50, 0x13, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00], // ldindb r1, 3, dst=3 (reserved field)
        [0x30, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00], // ldabsb 3, off=1 (reserved field)
        [0x50, 0x10, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00], // ldindb r1, 3, off=1 (reserved field)
        [0x30, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00], // ldabsb 3, src=1 (reserved field)
    ] {
        let prog = [
            [0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // mov r1, 0
            insn, // instruction under test
            [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // exit
        ]
        .concat();
        let err = match rbpf::EbpfVmNoData::new(Some(&prog)) {
            Ok(_) => panic!("{insn:02x?}: program accepted"),
            Err(e) => format!("{e:?}"),
        };
        assert!(
            err.contains("[Verifier] Error: BPF_LD_[ABS|IND] uses reserved fields (insn #1)"),
            "{insn:02x?}: {err}"
        );
    }
}

// Legacy packet loads not using reserved fields are accepted.
#[test]
fn test_verifier_ld_abs_ind() {
    let prog = assemble(
        "
        mov r1, 0
        ldabsb 3
        ldabsh 3
        ldabsw 3
        ldindb r1, 3
        ldindh r1, 3
        ldindw r1, 3
        exit",
    )
    .unwrap();
    rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
}

// Note: uBPF has test-err-incomplete-lddw2, which is the same
#[test]
#[should_panic(expected = "[Verifier] Error: incomplete LD_DW instruction (insn #0)")]
fn test_verifier_err_incomplete_lddw() {
    let prog = &[
        0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, // lddw r0, 0x55667788
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (lddw, upper 32 bits) exit
    ];
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: infinite loop")]
fn test_verifier_err_infinite_loop() {
    let prog = assemble(
        "
        ja -1
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: invalid destination register (insn #0)")]
fn test_verifier_err_invalid_reg_dst() {
    let prog = assemble(
        "
        mov r11, 1
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: invalid source register (insn #0)")]
fn test_verifier_err_invalid_reg_src() {
    let prog = assemble(
        "
        mov r0, r11
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: jump to middle of LD_DW at #2 (insn #0)")]
fn test_verifier_err_jmp_lddw() {
    let prog = assemble(
        "
        ja +1
        lddw r0, 0x1122334455667788
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: jump out of code to #3 (insn #0)")]
fn test_verifier_err_jmp_out() {
    let prog = assemble(
        "
        ja +2
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: program does not end with “EXIT” instruction")]
fn test_verifier_err_no_exit() {
    let prog = assemble(
        "
        mov32 r0, 0",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
fn test_verifier_err_no_exit_backward_jump() {
    let prog = assemble(
        "
        ja +1
        exit
        ja -2",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: eBPF program length limited to 1000000, here 1000001")]
fn test_verifier_err_too_many_instructions() {
    // uBPF uses 65637 instructions, because it sets its limit at 65636.
    // We use the classic 4096 limit from kernel, so no need to produce as many instructions.
    let mut prog = (0..(1_000_000 * ebpf::INSN_SIZE))
        .map(|x| match x % 8 {
            0 => 0xb7,
            1 => 0x01,
            _ => 0,
        })
        .collect::<Vec<u8>>();
    prog.append(&mut vec![0x95, 0, 0, 0, 0, 0, 0, 0]);

    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: unknown eBPF opcode 0x6 (insn #0)")]
fn test_verifier_err_unknown_opcode() {
    let prog = &[
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // unsupported opcode 0x06
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: cannot write into register r10 (insn #0)")]
fn test_verifier_err_write_r10() {
    let prog = assemble(
        "
        mov r10, 1
        exit
        ",
    )
    .unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: call out of code to #2 (insn #0)")]
fn test_verifier_err_funcall_over_the_end() {
    let prog = &[
        0x85, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // callx 1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();
}

#[test]
#[should_panic(expected = "[Verifier] Error: atomic operations other than legacy XADD are not supported (insn #0)")]
fn test_verifier_err_atomic_fetch_add() {
    // ST_W_XADD with imm = EBPF_ALU_OP_ADD | FETCH (newer atomic, not legacy XADD).
    let prog = &[
        0xc3, 0x21, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // stxxaddw [r1+0], r2, with fetch
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    vm.execute_program().unwrap();
}
