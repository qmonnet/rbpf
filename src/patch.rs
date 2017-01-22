// Copyright 2016 Quentin Monnet <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! Functions available in this module can patch an eBPF program before it is run. They are
//! provided as an attempt to bring more compatibility between programs intended for the Linux
//! kernel, and rbpf architecture.
//!
//! Currently, the only patching function tries to fix context accesses. But it is really
//! primitive, and works only on the simplest cases.

use ebpf;

/// A structure with an offset and a size, used in `struct MbuffStructure`, and in particular with
/// function `attempt_to_patch_prog()`.
#[derive(Default)]
pub struct MbuffField {
    /// The offset at which this value should be loaded in user-provided metadata buffer.
    pub offset: usize,
    /// The size this value occupies in user-provided metadata buffer.
    pub size:   usize,
}

/// A structure representing the fields of the Mbuff structure, as the user would like it to be
/// patched. See function `attempt_to_patch_prog()`.
///
/// Each attribute is a `struct MbuffField`, that has an offset and a size:
///
/// * The `offset` represents the desired offset for access to the relevant attribute in the
///   metabuffer data provided by the user.
/// * The `size` is the size of the data that should be loaded for the relevant attribute.
#[derive(Default)]
pub struct MbuffStructure {
    /// Offset and size for attribute `len` in user-provided metadata buffer.
    pub len:             MbuffField,
    /// Offset and size for attribute `pkt_type` in user-provided metadata buffer.
    pub pkt_type:        MbuffField,
    /// Offset and size for attribute `mark` in user-provided metadata buffer.
    pub mark:            MbuffField,
    /// Offset and size for attribute `queue_mapping` in user-provided metadata buffer.
    pub queue_mapping:   MbuffField,
    /// Offset and size for attribute `protocol` in user-provided metadata buffer.
    pub protocol:        MbuffField,
    /// Offset and size for attribute `vlan_present` in user-provided metadata buffer.
    pub vlan_present:    MbuffField,
    /// Offset and size for attribute `vlan_tci` in user-provided metadata buffer.
    pub vlan_tci:        MbuffField,
    /// Offset and size for attribute `vlan_proto` in user-provided metadata buffer.
    pub vlan_proto:      MbuffField,
    /// Offset and size for attribute `priority` in user-provided metadata buffer.
    pub priority:        MbuffField,
    /// Offset and size for attribute `ingress_ifindex` in user-provided metadata buffer.
    pub ingress_ifindex: MbuffField,
    /// Offset and size for attribute `ifindex` in user-provided metadata buffer.
    pub ifindex:         MbuffField,
    /// Offset and size for attribute `tc_index` in user-provided metadata buffer.
    pub tc_index:        MbuffField,
    /// Offset and size for attribute `cb` in user-provided metadata buffer.
    pub cb:              MbuffField,
    /// Offset and size for attribute `hash` in user-provided metadata buffer.
    pub hash:            MbuffField,
    /// Offset and size for attribute `tc_classid` in user-provided metadata buffer.
    pub tc_classid:      MbuffField,
    /// Offset and size for attribute `data` in user-provided metadata buffer.
    pub data:            MbuffField,
    /// Offset and size for attribute `data_end` in user-provided metadata buffer.
    pub data_end:        MbuffField,
}

/// An example `MbuffStructure` used to patch a program so that context access get compatible with
/// the Linux kernel. The `offset` and `size` of each attribute correspond to the offset and size
/// of the same respective attributes in the struct `__sk_buff` of the kernel.
///
/// **Work in progress**: these are not the actual values from the kernel for now.
///
/// The values were derived from tests with eBPF programs injected in the kernel, with a kernel
/// patched in order to dump the fixed context accesses.
///
/// Sadly, some of these values may vary depending on the architecture or on kernel version, so
/// your mileage may vary.
///
/// See also
/// <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/linux/skbuff.h>.
pub const KERNEL_SKBUFF: MbuffStructure = MbuffStructure {
    len:             MbuffField { offset: 0x0,  size: 0 }, // len
    pkt_type:        MbuffField { offset: 0x0,  size: 0 }, // 3insn
    mark:            MbuffField { offset: 0x0,  size: 0 }, // mark,
    queue_mapping:   MbuffField { offset: 0x0,  size: 0 }, // queue_mapping,
    protocol:        MbuffField { offset: 0x0,  size: 0 }, // protocol,
    vlan_present:    MbuffField { offset: 0x0,  size: 0 }, // vlan_tci,
    vlan_tci:        MbuffField { offset: 0x0,  size: 0 }, // vlan_tci + insns
    vlan_proto:      MbuffField { offset: 0x0,  size: 0 }, // vlan_proto,
    priority:        MbuffField { offset: 0x0,  size: 0 }, // priority,
    ingress_ifindex: MbuffField { offset: 0x0,  size: 0 }, // skb_iif,
    ifindex:         MbuffField { offset: 0x0,  size: 0 }, // 3 insns
    tc_index:        MbuffField { offset: 0x0,  size: 0 },
    cb:              MbuffField { offset: 0x0,  size: 0 }, // complex
    hash:            MbuffField { offset: 0x0,  size: 0 }, // hash,
    tc_classid:      MbuffField { offset: 0x0,  size: 0 }, // complex
    data:            MbuffField { offset: 0x40, size: 8 },
    data_end:        MbuffField { offset: 0x50, size: 8 },
};

fn create_patched_insn(reference_insn: &ebpf::Insn, field: &MbuffField) -> Option<ebpf::Insn> {
    let mut insn: ebpf::Insn = (*reference_insn).clone();

    match (insn.opc, field.size) {
        (ebpf::LD_W_REG, 1) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_B_REG;  },
        (ebpf::LD_W_REG, 2) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_H_REG;  },
        (ebpf::LD_W_REG, 4) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_W_REG;  },
        (ebpf::LD_W_REG, 8) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_DW_REG; },

        (ebpf::LD_ABS_W, 1) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_ABS_B;  },
        (ebpf::LD_ABS_W, 2) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_ABS_H;  },
        (ebpf::LD_ABS_W, 4) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_ABS_W;  },
        (ebpf::LD_ABS_W, 8) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_ABS_DW; },

        (ebpf::LD_IND_W, 1) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_IND_B;  },
        (ebpf::LD_IND_W, 2) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_IND_H;  },
        (ebpf::LD_IND_W, 4) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_IND_W;  },
        (ebpf::LD_IND_W, 8) => { insn.off = field.offset as i16; insn.opc = ebpf::LD_IND_DW; },

        (_, _)              => { },
    }

    if insn == *reference_insn {
        None
    } else {
        Some(insn)
    }
}

fn match_and_create_patched_insn(structure: &MbuffStructure, insn: &ebpf::Insn) -> Option<ebpf::Insn> {
    match insn.off {
        // All values in C struct are u32, except for cb.
        0x0  => create_patched_insn(insn, &structure.len),
        0x4  => create_patched_insn(insn, &structure.pkt_type),
        0x8  => create_patched_insn(insn, &structure.mark),
        0xc  => create_patched_insn(insn, &structure.queue_mapping),
        0x10 => create_patched_insn(insn, &structure.protocol),
        0x14 => create_patched_insn(insn, &structure.vlan_present),
        0x18 => create_patched_insn(insn, &structure.vlan_tci),
        0x1c => create_patched_insn(insn, &structure.vlan_proto),
        0x20 => create_patched_insn(insn, &structure.priority),
        0x24 => create_patched_insn(insn, &structure.ingress_ifindex),
        0x28 => create_patched_insn(insn, &structure.ifindex),
        0x2c => create_patched_insn(insn, &structure.tc_index),
        // cb points to a [u32;5], let 0x14 bytes between this one and next offset.
        0x30 => create_patched_insn(insn, &structure.cb),
        0x44 => create_patched_insn(insn, &structure.hash),
        0x48 => create_patched_insn(insn, &structure.tc_classid),
        0x4c => create_patched_insn(insn, &structure.data),
        0x50 => create_patched_insn(insn, &structure.data_end),
        // TODO: Not sure this is needed. Needs more tests with BPF and kernel.
        _    => {
            let offset = insn.off;
            create_patched_insn(insn, &MbuffField { offset: offset as usize, size: 8 })
        },
    }
}

fn apply_patched_insn(prog: &mut [u8], idx: usize, insn: ebpf::Insn) {
    for (i, &byte) in insn.to_vec().iter().enumerate() {
        prog[i + idx] = byte;
    }
}

// Wrapped by `attempt_to_patch_prog()`. See Rust-doc for that function.
fn patch_prog(prog: &mut [u8], structure: MbuffStructure) {
    // Store register state: true if pointer to context, false otherwise.
    let mut registers = [false;10]; // r0 to r9; r10 cannot point to context.

    // At the beginning of the program, assume r1 points to context.
    registers[1] = true;

    for (idx, insn) in ebpf::to_insn_vec(prog).iter().enumerate() {
        let (src, dst) = (insn.src as usize, insn.dst as usize);
        match insn.opc {
            // After moving a value from a register that points to the metadata buffer or packet
            // data, the destination register also points to the same memory area.
            ebpf::MOV32_REG | ebpf::MOV64_REG  => {
                // Update register state.
                registers[dst] = registers[src];
            },
            // After moving or loading an immediate value to a register, the latter does not point
            // to a metadata buffer or packet data.
            ebpf::MOV32_IMM | ebpf::MOV64_IMM | ebpf::LD_DW_IMM => {
                // Update register state.
                registers[dst] = false;
            },
            // Absolute or indirect load from context are explicit context accesses.
            ebpf::LD_ABS_B | ebpf::LD_ABS_H | ebpf::LD_ABS_W | ebpf::LD_ABS_DW |
            ebpf::LD_IND_B | ebpf::LD_IND_H | ebpf::LD_IND_W | ebpf::LD_IND_DW => {
                // Update register state.
                registers[dst] = true;
                unimplemented!();
            },
            // Loading a word from a register may be a context access. We use the current state of
            // the register to determine whether this is the case. If it is, we attempt to patch
            // the instruction.
            ebpf::LD_W_REG => {
                // Update register state.
                registers[dst] = registers[src];
                // Update context access, if relevant.
                if registers[dst] {
                    if let Some(patched_insn) = match_and_create_patched_insn(&structure, insn) {
                        apply_patched_insn(prog, idx * ebpf::INSN_SIZE, patched_insn);
                    }
                }
            },
            // All other instructions have no effect on registers' state and do not trigger
            // patching attempts.
            _  => {},
        }
    }
}

/// Attempt to patch a program in-place in order to fix context accesses. **Highly experimental**.
/// Provided for tests, feedback and improvement, do not use in production!
///
/// This function is a poor attempt at emulating the program patching that happens for context
/// accesses in Linux kernel. It should be only relevant when using virtual machines working on a
/// memory area, in particular with a metadata buffer.
///
/// Specifically, when an eBPF program is injected into the kernel, it undergoes a series of checks
/// and a couple of fixing, including for what is called “context accesses”, or in other words,
/// accesses to the memory area the program is expected to work with.
///
/// The rough principle is the following:
///
/// * When compiled with clang, the program sets offsets to some particular fields of the metadata
///   buffer in accordance to a special `struct __sk_buff` (see
///   <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h>).
///   For example, the first attribute of this struct is `len`, with offset `0` inside the struct.
///   So when the eBPF program attempts to read `len` in the metadata buffer, it reaches at offset
///   `0` in the metadata buffer. For `data`, it is offset `0x4c`: this is why, again, compiled
///   programs try to load packet data from the pointer at this offset in the metadata buffer.
///
/// * But in the kernel, the `sk_buff` structure used for real packets is not the same, and the
///   offsets of `len` or `data` in that structure differ with the one of `__sk_buff`. So the eBPF
///   program is patched: all instructions loading 4 bytes from the metadata buffer at the offset
///   of `data` attribute (of `__sk_buff`) are turned into instructions loading 8 bytes from the
///   offset of `data` attribute in struct `sk_buff`, so that when receiving a `sk_buff`, the
///   program is able to load the correct value.
///
/// `len` or `data` are amongst the simple cases, since for some attributes the fix requires more
/// than a simple mapping to the corresponding offset (some additional eBPF instructions may
/// occasionally be required).
///
/// Now if we try to do the same in rbpf, the principal difficulty is in identifying what
/// instructions represent context accesses, and to what field of the `__sk_buff`. Ideally, we
/// would need to parse the program and to update states for registers depending on the instruction
/// contents, which is not easy when we account for jumps. And we would need to track the values in
/// those registers to get the correct attributes that the program tries to reach. All of this
/// without reusing the GPL code of the kernel…
///
/// The current compromise is a simple heuristic program that tries to assign simple states to
/// registers (`true` or `false`, depending on whether it contains an address to metadata buffer or
/// not), but not accounting for jumps or tracking offsets. It may work on very simple cases and is
/// certain to fail on complex ones. Maybe we will manage to improve it somehow.
///
/// Feedback or improvement ideas are very welcome.
///
/// # Examples:
///
/// ```
/// use rbpf::patch;
///
///  // The following program:
///  //
///  // 1. Loads `data` and `data_end` from metadata buffer.
///  // 2. Checks that `data` + 14 <= `data_end`. Exit otherwise.
///  // 3. Loads two bytes in packet data, at `data + 14` (in other words: ethertype).
///  // 4. r0 = to_big_endian(r0) && return r0.
///  let prog = &mut [
///      0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
///      0x61, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxw r2, r1[0x50]
///      0x61, 0x11, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, // lddw r1, r1[Ox4c]
///      0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r3, r1
///      0x07, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, // add r3, 0x0c
///      0x2d, 0x23, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // jgt r3, r2, +2
///      0x69, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxh r0, r1[0x0c]
///      0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r0
///      0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
/// ];
///
/// let packet = &mut [
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
///     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
///     0x08, 0x00,             // ethertype
///     0x45, 0x00, 0x00, 0x3b, // start ip_hdr
///     0xa6, 0xab, 0x40, 0x00,
///     0x40, 0x06, 0x96, 0x0f,
///     0x7f, 0x00, 0x00, 0x01,
///     0x7f, 0x00, 0x00, 0x01,
///     0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
///     0xd1, 0xe5, 0xc4, 0x9d,
///     0xd4, 0x30, 0xb5, 0xd2,
///     0x80, 0x18, 0x01, 0x56,
///     0xfe, 0x2f, 0x00, 0x00,
///     0x01, 0x01, 0x08, 0x0a, // start data
///     0x00, 0x23, 0x75, 0x89,
///     0x00, 0x23, 0x63, 0x2d,
///     0x71, 0x64, 0x66, 0x73,
///     0x64, 0x66, 0x0au8
/// ];
///
/// // For this program to work, we need the two loads to metadata buffer, starting with `0x61`
/// // operation code, to load 8 bytes from the offsets we want for `data` and `data_end`, instead
/// // of loading 4 bytes from offsets generated by clang. We do this by patching the program.
/// //
/// // Indeed, we could not load the memory address of the packet from 4 bytes only. And the
/// // offsets generated by clang are too close to insert the 8 bytes for `data` without
/// // overlapping with `data_end`.
///
/// // First define the offsets and sizes we want.
/// let mut my_mbuff_structure: patch::MbuffStructure = Default::default();
/// my_mbuff_structure.data     = patch::MbuffField { offset: 0x40, size: 8 };
/// my_mbuff_structure.data_end = patch::MbuffField { offset: 0x50, size: 8 };
///
/// // Try to patch. This example should work.
/// patch::attempt_to_patch_prog(prog, my_mbuff_structure);
/// println!("{:?}", prog.to_vec());
///
/// // Create a virtual machine with a metadata buffer (here a fixed one, that is automatically
/// // updated for each packet to contain `data` and `data_offset` at the offsets we want).
/// let mut vm = rbpf::EbpfVmFixedMbuff::new(prog, 0x40, 0x50);
///
/// // Now we can run the program.
/// let res = vm.prog_exec(packet);
/// assert_eq!(res, 0x0800);
/// ```
pub fn attempt_to_patch_prog(prog: &mut [u8], structure: MbuffStructure) {
    println!("Warning: patching context accesses is experimental, works for the simplest cases.");
    println!("It may break you program!");
    patch_prog(prog, structure)
}

mod test {
    // Can't figure out how to get rid of the warning here. Probably we're not supposed to add a
    // test module in a non-root module? This is temporary anyway.
     #[allow(unused_imports)]
    use super::*;
     #[allow(unused_imports)]
    use ebpf;

    #[test]
    fn patch_and_compare() {
        let prog = &mut [
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x61, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x61, 0x11, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
            0x2d, 0x23, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x69, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x55, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x71, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x55, 0x02, 0x0e, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x61, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x15, 0x02, 0x08, 0x00, 0x99, 0x99, 0x00, 0x00,
            0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x5f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        let target_prog = &[
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x79, 0x12, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
            0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61, 0x40 i.o. 0x4c
            0xbf, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
            0x2d, 0x23, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x69, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x55, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x71, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x55, 0x02, 0x0e, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x79, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x79 instead of 0x61
            0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x15, 0x02, 0x08, 0x00, 0x99, 0x99, 0x00, 0x00,
            0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x5f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        attempt_to_patch_prog(prog, KERNEL_SKBUFF);

        let target_insns = ebpf::to_insn_vec(target_prog);
        let mut target = target_insns.iter();

        for insn in ebpf::to_insn_vec(prog) {
            assert_eq!(insn, *target.next().unwrap());
        }
    }
}
