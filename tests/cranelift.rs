// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg(feature = "cranelift")]

extern crate rbpf;
mod common;

use rbpf::assembler::assemble;

macro_rules! test_cranelift {
    ($name:ident, $prog:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let prog = assemble($prog).unwrap();
            let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
            assert_eq!(vm.execute_cranelift().unwrap(), $expected);
        }
    };
    ($name:ident, $prog:expr, $mem:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let prog = assemble($prog).unwrap();
            let mem = &mut $mem;
            let vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
            assert_eq!(vm.execute_cranelift(mem).unwrap(), $expected);
        }
    };
}

test_cranelift!(
    test_cranelift_add,
    "
    mov32 r0, 0
    mov32 r1, 2
    add32 r0, 1
    add32 r0, r1
    exit
    ",
    0x3
);

test_cranelift!(
    test_cranelift_alu64_arith,
    "
    mov r0, 0
    mov r1, 1
    mov r2, 2
    mov r3, 3
    mov r4, 4
    mov r5, 5
    mov r6, 6
    mov r7, 7
    mov r8, 8
    mov r9, 9
    add r0, 23
    add r0, r7
    sub r0, 13
    sub r0, r1
    mul r0, 7
    mul r0, r3
    div r0, 2
    div r0, r4
    exit
    ",
    0x2a
);

test_cranelift!(
    test_cranelift_alu64_bit,
    "
    mov r0, 0
    mov r1, 1
    mov r2, 2
    mov r3, 3
    mov r4, 4
    mov r5, 5
    mov r6, 6
    mov r7, 7
    mov r8, 8
    or r0, r5
    or r0, 0xa0
    and r0, 0xa3
    mov r9, 0x91
    and r0, r9
    lsh r0, 32
    lsh r0, 22
    lsh r0, r8
    rsh r0, 32
    rsh r0, 19
    rsh r0, r7
    xor r0, 0x03
    xor r0, r2
    exit
    ",
    0x11
);

test_cranelift!(
    test_cranelift_alu_arith,
    "
    mov32 r0, 0
    mov32 r1, 1
    mov32 r2, 2
    mov32 r3, 3
    mov32 r4, 4
    mov32 r5, 5
    mov32 r6, 6
    mov32 r7, 7
    mov32 r8, 8
    mov32 r9, 9
    add32 r0, 23
    add32 r0, r7
    sub32 r0, 13
    sub32 r0, r1
    mul32 r0, 7
    mul32 r0, r3
    div32 r0, 2
    div32 r0, r4
    exit
    ",
    0x2a
);

test_cranelift!(
    test_cranelift_alu_bit,
    "
    mov32 r0, 0
    mov32 r1, 1
    mov32 r2, 2
    mov32 r3, 3
    mov32 r4, 4
    mov32 r5, 5
    mov32 r6, 6
    mov32 r7, 7
    mov32 r8, 8
    or32 r0, r5
    or32 r0, 0xa0
    and32 r0, 0xa3
    mov32 r9, 0x91
    and32 r0, r9
    lsh32 r0, 22
    lsh32 r0, r8
    rsh32 r0, 19
    rsh32 r0, r7
    xor32 r0, 0x03
    xor32 r0, r2
    exit
    ",
    0x11
);

test_cranelift!(
    test_cranelift_arsh32_high_shift,
    "
    mov r0, 8
    lddw r1, 0x100000001
    arsh32 r0, r1
    exit
    ",
    0x4
);

test_cranelift!(
    test_cranelift_arsh,
    "
    mov32 r0, 0xf8
    lsh32 r0, 28
    arsh32 r0, 16
    exit
    ",
    0xffff8000
);

test_cranelift!(
    test_cranelift_arsh64,
    "
    mov32 r0, 1
    lsh r0, 63
    arsh r0, 55
    mov32 r1, 5
    arsh r0, r1
    exit
    ",
    0xfffffffffffffff8
);

test_cranelift!(
    test_cranelift_arsh_reg,
    "
    mov32 r0, 0xf8
    mov32 r1, 16
    lsh32 r0, 28
    arsh32 r0, r1
    exit
    ",
    0xffff8000
);
