// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2024 Akenes SA <wouter.dullaert@exoscale.ch>

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_PIPE},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

#[map]
static RULES: HashMap<Key, Value> = HashMap::<Key, Value>::with_max_entries(1, BPF_F_NO_PREALLOC);

#[repr(C, packed)]
pub struct Key {
    pub protocol: u8,
}

#[repr(C, packed)]
pub struct Value {
    pub result: i32,
}

#[classifier]
pub fn ingress_tc(_ctx: TcContext) -> i32 {
    let key = Key { protocol: 1 };
    if let Some(action) = unsafe { RULES.get(&key) } {
        return action.result;
    }
    return TC_ACT_PIPE;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
