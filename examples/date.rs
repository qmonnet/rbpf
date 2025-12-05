// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2017 6WIND S.A. <quentin.monnet@6wind.com>

extern crate rbpf;

use std::time::{SystemTime, UNIX_EPOCH};

// The main objectives of this example is to show:
//
// * the use of EbpfVmNoData function,
// * and the use of a custom helper.
//
// The two eBPF programs are independent and are not related to one another.

// Custom helper that returns the current Unix timestamp in seconds.
// This demonstrates how users can create and register their own helpers with rbpf.
#[allow(unused_variables)]
fn helper_get_time_sec(unused1: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper index for our custom helper (using an arbitrary unused index).
const HELPER_GET_TIME_SEC_IDX: u32 = 0x01;

fn main() {
    #[rustfmt::skip]
    let prog1 = &[
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit and return r0
    ];

    // We define a custom helper `helper_get_time_sec()` that returns the current
    // Unix timestamp in seconds. This shows how users can create their own helpers
    // and register them with the VM.
    let hkey = HELPER_GET_TIME_SEC_IDX as u8;
    #[rustfmt::skip]
    let prog2 = &[
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r2, 0
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r3, 0
        0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r4, 0
        0xb7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r5, 0
        0x85, 0x00, 0x00, 0x00, hkey, 0x00, 0x00, 0x00, // call helper <hkey>
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit and return r0
    ];

    // Create a VM: this one takes no data. Load prog1 in it.
    let mut vm = rbpf::EbpfVmNoData::new(Some(prog1)).unwrap();
    // Execute prog1.
    assert_eq!(vm.execute_program().unwrap(), 0x3);

    // As struct EbpfVmNoData does not takes any memory area, its return value is mostly
    // deterministic. So we know prog1 will always return 3. There is an exception: when it uses
    // helpers, the latter may have non-deterministic values, and all calls may not return the same
    // value.
    //
    // In the following example we use a custom helper to get the current Unix timestamp.
    // This demonstrates how to register and use custom helpers in eBPF programs.

    vm.set_program(prog2).unwrap();
    vm.register_helper(HELPER_GET_TIME_SEC_IDX, helper_get_time_sec)
        .unwrap();

    let time;

    #[cfg(all(not(windows), feature = "std"))]
    {
        vm.jit_compile().unwrap();

        time = unsafe { vm.execute_program_jit().unwrap() };
    }

    #[cfg(any(windows, not(feature = "std")))]
    {
        time = vm.execute_program().unwrap();
    }

    print_date(time);
}

#[rustfmt::skip]
fn print_date(timestamp: u64) {
    // Convert Unix timestamp to a human-readable date

    // Constants for date calculation
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
    const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

    // Days in each month (non-leap year)
    const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    fn is_leap_year(year: u64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    fn days_in_year(year: u64) -> u64 {
        if is_leap_year(year) { 366 } else { 365 }
    }

    // Calculate time components
    let seconds = timestamp % SECONDS_PER_MINUTE;
    let minutes = (timestamp / SECONDS_PER_MINUTE) % 60;
    let hours = (timestamp / SECONDS_PER_HOUR) % 24;

    // Calculate date
    let mut remaining_days = timestamp / SECONDS_PER_DAY;
    let mut year = 1970u64;

    while remaining_days >= days_in_year(year) {
        remaining_days -= days_in_year(year);
        year += 1;
    }

    let mut month = 0usize;
    while month < 12 {
        let days = if month == 1 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[month]
        };

        if remaining_days < days {
            break;
        }
        remaining_days -= days;
        month += 1;
    }

    let day = remaining_days + 1;
    let month = month + 1;

    println!("Current date and time (UTC): {year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}");
    println!("Unix timestamp: {timestamp}");
}

