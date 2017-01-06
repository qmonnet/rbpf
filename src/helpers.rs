// Copyright 2015 Big Switch Networks, Inc
//      (Algorithms for uBPF helpers, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, other helpers)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


use std::u64;

// Helpers associated to kernel helpers
// See also linux/include/uapi/linux/bpf.h in Linux kernel sources.

// bpf_trace_printk()
// No side effect: just print arg3, arg4 and arg5 to standard output.
pub const BPF_TRACE_PRINTF_IDX: u32 = 6;

#[allow(dead_code)]
#[allow(unused_variables)]
pub fn bpf_trace_printf (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    println!("bpf_trace_printf: {:#x}, {:#x}, {:#x}", arg3, arg4, arg5);
    0
}


// Helpers coming from uBPF <https://github.com/iovisor/ubpf/blob/master/vm/test.c>

pub fn gather_bytes (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    arg1.wrapping_shl(32) |
    arg2.wrapping_shl(24) |
    arg3.wrapping_shl(16) |
    arg4.wrapping_shl(8)  |
    arg5
}

#[allow(unused_variables)]
pub fn memfrob (ptr: u64, len: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    for i in 0..len {
        unsafe {
            let mut p = (ptr + i) as *mut u8;
            *p ^= 0b101010;
        }
    }
    0
}


// TODO: Try again when asm!() is available in stable Rust.
// #![feature(asm)]
// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// #[allow(unused_variables)]
// pub fn memfrob (ptr: u64, len: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
//     unsafe {
//         asm!(
//                 "mov $0xf0, %rax"
//             ::: "mov $0xf1, %rcx"
//             ::: "mov $0xf2, %rdx"
//             ::: "mov $0xf3, %rsi"
//             ::: "mov $0xf4, %rdi"
//             ::: "mov $0xf5, %r8"
//             ::: "mov $0xf6, %r9"
//             ::: "mov $0xf7, %r10"
//             ::: "mov $0xf8, %r11"
//         );
//     }
//     0
// }

#[allow(dead_code)]
#[allow(unused_variables)]
pub fn sqrti (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    // Warning: untested
    (arg1 as f64).sqrt() as u64
}

#[allow(dead_code)]
#[allow(unused_variables)]
pub fn strcmp (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    // C-like strcmp, maybe shorter than converting the bytes to string and comparing?
    if arg1 == 0 || arg2 == 0 {
        return u64::MAX;
    }
    let mut a = arg1;
    let mut b = arg2;
    unsafe {
        let mut a_val = *(a as *const u8);
        let mut b_val = *(b as *const u8);
        while a_val == b_val && a_val != 0 && b_val != 0 {
            a +=1 ;
            b +=1 ;
            a_val = *(a as *const u8);
            b_val = *(b as *const u8);
        }
        if a_val >= b_val {
            (a_val - b_val) as u64
        } else {
            (b_val - a_val) as u64
        }
    }
}
