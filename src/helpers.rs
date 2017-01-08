// Copyright 2015 Big Switch Networks, Inc
//      (Algorithms for uBPF helpers, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, other helpers)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! This module implements some built-in helpers that can be called from within an eBPF program.
//!
//! These helpers may originate from several places:
//!
//! * Some of them mimic the helpers available in the Linux kernel.
//! * Some of them were proposed as example helpers in uBPF and they were adapted here.
//! * Other helpers may be specific to rbpf.
//!
//! The prototype for helpers is always the same: five `u64` as arguments, and a `u64` as a return
//! value. Hence some helpers have unused arguments, or return a 0 value in all cases, in order to
//! respect this convention.

use std::u64;

// Helpers associated to kernel helpers
// See also linux/include/uapi/linux/bpf.h in Linux kernel sources.

// bpf_trace_printk()

/// Index of helper `bpf_trace_printk()`, equivalent to `bpf_trace_printf()`, in Linux kernel, see
/// <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h>.
pub const BPF_TRACE_PRINTK_IDX: u32 = 6;

/// Prints its **last three** arguments to standard output. The **first two** arguments are
/// **unused**. Returns 0.
///
/// By ignoring the first two arguments, it creates a helper that will have a behavior similar to
/// the one of the equivalent helper `bpf_trace_printk()` from Linux kernel.
///
/// # Examples
///
/// ```
/// use rbpf::helpers;
///
/// helpers::bpf_trace_printf(1, 15, 32, 0, 0);
/// ```
///
/// This will print `bpf_trace_printf: 0x1, 0xf, 0x20`.
///
/// The eBPF code produced would be nearly the same as when compiling the following code from C to
/// eBPF with clang:
///
/// ```c
/// #include <linux/bpf.h>
/// #include "path/to/linux/samples/bpf/bpf_helpers.h"
///
/// int main(struct __sk_buff *skb)
/// {
///     char *fmt = "bpf_trace_printk %lx %lx %lx\n";
///     return bpf_trace_printk(fmt, sizeof(fmt), 1, 15, 32);
/// }
/// ```
///
/// This would equally print the three numbers in `/sys/kernel/debug/tracing` file each time the
/// program is run.
#[allow(dead_code)]
#[allow(unused_variables)]
pub fn bpf_trace_printf (unused1: u64, unused2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    println!("bpf_trace_printf: {:#x}, {:#x}, {:#x}", arg3, arg4, arg5);
    0
}


// Helpers coming from uBPF <https://github.com/iovisor/ubpf/blob/master/vm/test.c>

/// The idea is to assemble five bytes into a single `u64`. For compatibility with the helpers API,
/// each argument must be a `u64`.
///
/// # Examples
///
/// ```
/// use rbpf::helpers;
///
/// let gathered = helpers::gather_bytes(0x11, 0x22, 0x33, 0x44, 0x55);
/// assert_eq!(gathered, 0x1122334455);
/// ```
pub fn gather_bytes (arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    arg1.wrapping_shl(32) |
    arg2.wrapping_shl(24) |
    arg3.wrapping_shl(16) |
    arg4.wrapping_shl(8)  |
    arg5
}

/// Same as `void *memfrob(void *s, size_t n);` in `string.h` in C. See the GNU manual page (in
/// section 3) for `memfrob`. The memory is directly modified, and the helper returns 0 in all
/// cases. Arguments 3 to 5 are unused.
///
/// # Examples
///
/// ```
/// use rbpf::helpers;
///
/// let val: u64 = 0x112233;
/// let val_ptr = &val as *const u64;
///
/// helpers::memfrob(val_ptr as u64, 8, 0, 0, 0);
/// assert_eq!(val, 0x2a2a2a2a2a3b0819);
/// helpers::memfrob(val_ptr as u64, 8, 0, 0, 0);
/// assert_eq!(val, 0x112233);
/// ```
#[allow(unused_variables)]
pub fn memfrob (ptr: u64, len: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
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

/// Compute and return the square root of argument 1, cast as a float. Arguments 2 to 5 are
/// unused.
///
/// # Examples
///
/// ```
/// use rbpf::helpers;
///
/// let x = helpers::sqrti(9, 0, 0, 0, 0);
/// assert_eq!(x, 3);
/// ```
#[allow(dead_code)]
#[allow(unused_variables)]
pub fn sqrti (arg1: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    (arg1 as f64).sqrt() as u64
}

/// C-like `strcmp`, return 0 if the strings are equal, and a non-null value otherwise.
///
/// # Examples
///
/// ```
/// use rbpf::helpers;
///
/// let foo = "This is a string.".as_ptr() as u64;
/// let bar = "This is another sting.".as_ptr() as u64;
///
/// assert!(helpers::strcmp(foo, foo, 0, 0, 0) == 0);
/// assert!(helpers::strcmp(foo, bar, 0, 0, 0) != 0);
/// ```
#[allow(dead_code)]
#[allow(unused_variables)]
pub fn strcmp (arg1: u64, arg2: u64, arg3: u64, unused4: u64, unused5: u64) -> u64 {
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
