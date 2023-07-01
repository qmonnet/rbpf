// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg(feature = "cranelift")]

extern crate rbpf;
mod common;

use rbpf::{assembler::assemble, helpers};

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

test_cranelift!(
    test_cranelift_be16,
    "
    ldxh r0, [r1]
    be16 r0
    exit
    ",
    [0x11, 0x22],
    0x1122
);

test_cranelift!(
    test_cranelift_be16_high,
    "
    ldxdw r0, [r1]
    be16 r0
    exit
    ",
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    0x1122
);

test_cranelift!(
    test_cranelift_be32,
    "
    ldxw r0, [r1]
    be32 r0
    exit
    ",
    [0x11, 0x22, 0x33, 0x44],
    0x11223344
);

test_cranelift!(
    test_cranelift_be32_high,
    "
    ldxdw r0, [r1]
    be32 r0
    exit
    ",
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    0x11223344
);

test_cranelift!(
    test_cranelift_be64,
    "
    ldxdw r0, [r1]
    be64 r0
    exit
    ",
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    0x1122334455667788
);

#[test]
fn test_cranelift_call() {
    let prog = assemble(
        "
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        call 0
        exit",
    )
    .unwrap();

    let mut vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    vm.register_helper(0, helpers::gather_bytes).unwrap();
    assert_eq!(vm.execute_cranelift().unwrap(), 0x0102030405);
}

#[test]
fn test_cranelift_call_memfrob() {
    let prog = assemble(
        "
        mov r6, r1
        add r1, 2
        mov r2, 4
        call 1
        ldxdw r0, [r6]
        be64 r0
        exit",
    )
    .unwrap();

    let mut vm = rbpf::EbpfVmRaw::new(Some(&prog)).unwrap();
    vm.register_helper(1, helpers::memfrob).unwrap();
    let mem = &mut [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(vm.execute_cranelift(mem).unwrap(), 0x102292e2f2c0708);
}

test_cranelift!(
    test_cranelift_div32_high_divisor,
    "
    mov r0, 12
    lddw r1, 0x100000004
    div32 r0, r1
    exit
    ",
    0x3
);

test_cranelift!(
    test_cranelift_div32_imm,
    "
    lddw r0, 0x10000000c
    div32 r0, 4
    exit
    ",
    0x3
);

test_cranelift!(
    test_cranelift_div32_reg,
    "
    lddw r0, 0x10000000c
    mov r1, 4
    div32 r0, r1
    exit
    ",
    0x3
);

test_cranelift!(
    test_cranelift_div64_imm,
    "
    mov r0, 0xc
    lsh r0, 32
    div r0, 4
    exit
    ",
    0x300000000
);

test_cranelift!(
    test_cranelift_div64_reg,
    "
    mov r0, 0xc
    lsh r0, 32
    mov r1, 4
    div r0, r1
    exit
    ",
    0x300000000
);

test_cranelift!(
    test_cranelift_div64_by_zero_imm,
    "
    mov32 r0, 1
    div r0, 0
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_div_by_zero_imm,
    "
    mov32 r0, 1
    div32 r0, 0
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_mod64_by_zero_imm,
    "
    mov32 r0, 1
    mod r0, 0
    exit
    ",
    0x1
);

test_cranelift!(
    test_cranelift_mod_by_zero_imm,
    "
    mov32 r0, 1
    mod32 r0, 0
    exit
    ",
    0x1
);

test_cranelift!(
    test_cranelift_div64_by_zero_reg,
    "
    mov32 r0, 1
    mov32 r1, 0
    div r0, r1
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_div_by_zero_reg,
    "
    mov32 r0, 1
    mov32 r1, 0
    div32 r0, r1
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_mod64_by_zero_reg,
    "
    mov32 r0, 1
    mov32 r1, 0
    mod r0, r1
    exit
    ",
    0x1
);

test_cranelift!(
    test_cranelift_mod_by_zero_reg,
    "
    mov32 r0, 1
    mov32 r1, 0
    mod32 r0, r1
    exit
    ",
    0x1
);

test_cranelift!(
    test_cranelift_exit,
    "
    mov r0, 0
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_lddw,
    "
    lddw r0, 0x1122334455667788
    exit
    ",
    0x1122334455667788
);

test_cranelift!(
    test_cranelift_lddw2,
    "
    lddw r0, 0x0000000080000000
    exit
    ",
    0x80000000
);

test_cranelift!(
    test_cranelift_ldxb_all,
    "
    mov r0, r1
    ldxb r9, [r0+0]
    lsh r9, 0
    ldxb r8, [r0+1]
    lsh r8, 4
    ldxb r7, [r0+2]
    lsh r7, 8
    ldxb r6, [r0+3]
    lsh r6, 12
    ldxb r5, [r0+4]
    lsh r5, 16
    ldxb r4, [r0+5]
    lsh r4, 20
    ldxb r3, [r0+6]
    lsh r3, 24
    ldxb r2, [r0+7]
    lsh r2, 28
    ldxb r1, [r0+8]
    lsh r1, 32
    ldxb r0, [r0+9]
    lsh r0, 36
    or r0, r1
    or r0, r2
    or r0, r3
    or r0, r4
    or r0, r5
    or r0, r6
    or r0, r7
    or r0, r8
    or r0, r9
    exit
    ",
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
    0x9876543210
);

test_cranelift!(
    test_cranelift_ldxb,
    "
    ldxb r0, [r1+2]
    exit
    ",
    [0xaa, 0xbb, 0x11, 0xcc, 0xdd],
    0x11
);

test_cranelift!(
    test_cranelift_ldxdw,
    "
    ldxdw r0, [r1+2]
    exit
    ",
    [0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xcc, 0xdd],
    0x8877665544332211
);

test_cranelift!(
    test_cranelift_ldxh_all,
    "
    mov r0, r1
    ldxh r9, [r0+0]
    be16 r9
    lsh r9, 0
    ldxh r8, [r0+2]
    be16 r8
    lsh r8, 4
    ldxh r7, [r0+4]
    be16 r7
    lsh r7, 8
    ldxh r6, [r0+6]
    be16 r6
    lsh r6, 12
    ldxh r5, [r0+8]
    be16 r5
    lsh r5, 16
    ldxh r4, [r0+10]
    be16 r4
    lsh r4, 20
    ldxh r3, [r0+12]
    be16 r3
    lsh r3, 24
    ldxh r2, [r0+14]
    be16 r2
    lsh r2, 28
    ldxh r1, [r0+16]
    be16 r1
    lsh r1, 32
    ldxh r0, [r0+18]
    be16 r0
    lsh r0, 36
    or r0, r1
    or r0, r2
    or r0, r3
    or r0, r4
    or r0, r5
    or r0, r6
    or r0, r7
    or r0, r8
    or r0, r9
    exit
    ",
    [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
        0x07, 0x00, 0x08, 0x00, 0x09
    ],
    0x9876543210
);

test_cranelift!(
    test_cranelift_ldxh_all2,
    "
    mov r0, r1
    ldxh r9, [r0+0]
    be16 r9
    ldxh r8, [r0+2]
    be16 r8
    ldxh r7, [r0+4]
    be16 r7
    ldxh r6, [r0+6]
    be16 r6
    ldxh r5, [r0+8]
    be16 r5
    ldxh r4, [r0+10]
    be16 r4
    ldxh r3, [r0+12]
    be16 r3
    ldxh r2, [r0+14]
    be16 r2
    ldxh r1, [r0+16]
    be16 r1
    ldxh r0, [r0+18]
    be16 r0
    or r0, r1
    or r0, r2
    or r0, r3
    or r0, r4
    or r0, r5
    or r0, r6
    or r0, r7
    or r0, r8
    or r0, r9
    exit
    ",
    [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x08, 0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0x00,
        0x80, 0x01, 0x00, 0x02, 0x00
    ],
    0x3ff
);

test_cranelift!(
    test_cranelift_ldxh,
    "
    ldxh r0, [r1+2]
    exit
    ",
    [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd],
    0x2211
);

test_cranelift!(
    test_cranelift_ldxw_all,
    "
    mov r0, r1
    ldxw r9, [r0+0]
    be32 r9
    ldxw r8, [r0+4]
    be32 r8
    ldxw r7, [r0+8]
    be32 r7
    ldxw r6, [r0+12]
    be32 r6
    ldxw r5, [r0+16]
    be32 r5
    ldxw r4, [r0+20]
    be32 r4
    ldxw r3, [r0+24]
    be32 r3
    ldxw r2, [r0+28]
    be32 r2
    ldxw r1, [r0+32]
    be32 r1
    ldxw r0, [r0+36]
    be32 r0
    or r0, r1
    or r0, r2
    or r0, r3
    or r0, r4
    or r0, r5
    or r0, r6
    or r0, r7
    or r0, r8
    or r0, r9
    exit
    ",
    [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
    ],
    0x030f0f
);

test_cranelift!(
    test_cranelift_ldxw,
    "
    ldxw r0, [r1+2]
    exit
    ",
    [0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd],
    0x44332211
);

test_cranelift!(
    test_cranelift_le16,
    "
    ldxh r0, [r1]
    le16 r0
    exit
    ",
    [0x22, 0x11],
    0x1122
);

test_cranelift!(
    test_cranelift_le32,
    "
    ldxw r0, [r1]
    le32 r0
    exit
    ",
    [0x44, 0x33, 0x22, 0x11],
    0x11223344
);

test_cranelift!(
    test_cranelift_le64,
    "
    ldxdw r0, [r1]
    le64 r0
    exit
    ",
    [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    0x1122334455667788
);

test_cranelift!(
    test_cranelift_lsh_reg,
    "
    mov r0, 0x1
    mov r7, 4
    lsh r0, r7
    exit
    ",
    0x10
);

test_cranelift!(
    test_cranelift_mod,
    "
    mov32 r0, 5748
    mod32 r0, 92
    mov32 r1, 13
    mod32 r0, r1
    exit
    ",
    0x5
);

test_cranelift!(
    test_cranelift_mod32,
    "
    lddw r0, 0x100000003
    mod32 r0, 3
    exit
    ",
    0x0
);

test_cranelift!(
    test_cranelift_mod64,
    "
    mov32 r0, -1316649930
    lsh r0, 32
    or r0, 0x100dc5c8
    mov32 r1, 0xdde263e
    lsh r1, 32
    or r1, 0x3cbef7f3
    mod r0, r1
    mod r0, 0x658f1778
    exit
    ",
    0x30ba5a04
);

test_cranelift!(
    test_cranelift_mov,
    "
    mov32 r1, 1
    mov32 r0, r1
    exit
    ",
    0x1
);

test_cranelift!(
    test_cranelift_mul32_imm,
    "
    mov r0, 3
    mul32 r0, 4
    exit
    ",
    0xc
);

test_cranelift!(
    test_cranelift_mul32_reg,
    "
    mov r0, 3
    mov r1, 4
    mul32 r0, r1
    exit
    ",
    0xc
);

test_cranelift!(
    test_cranelift_mul32_reg_overflow,
    "
    mov r0, 0x40000001
    mov r1, 4
    mul32 r0, r1
    exit
    ",
    0x4
);

test_cranelift!(
    test_cranelift_mul64_imm,
    "
    mov r0, 0x40000001
    mul r0, 4
    exit
    ",
    0x100000004
);

test_cranelift!(
    test_cranelift_mul64_reg,
    "
    mov r0, 0x40000001
    mov r1, 4
    mul r0, r1
    exit
    ",
    0x100000004
);
