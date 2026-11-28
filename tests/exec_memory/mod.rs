// SPDX-License-Identifier: (Apache-2.0 OR MIT)

// Executable memory for the JIT in no_std tests, where rbpf cannot allocate it itself.

use std::ops::{Deref, DerefMut};

const SIZE: usize = 4096;

/// A page of memory mapped readable, writable and executable, unmapped on drop.
pub struct ExecMemory {
    ptr: *mut u8,
}

impl Deref for ExecMemory {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, SIZE) }
    }
}

impl DerefMut for ExecMemory {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, SIZE) }
    }
}

impl Drop for ExecMemory {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), SIZE) };
    }
}

// Map a fresh page rather than changing the protection of heap memory: mprotect() may cover other
// allocations sharing the page, and security policies such as SELinux's execheap may forbid making
// heap memory executable.
pub fn alloc_exec_memory() -> ExecMemory {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        ptr,
        libc::MAP_FAILED,
        "Failed to map executable memory: {}",
        std::io::Error::last_os_error()
    );
    ExecMemory { ptr: ptr.cast() }
}
