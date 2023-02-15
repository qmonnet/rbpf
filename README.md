# rbpf

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="misc/rbpf_256_border.png">
  <img src="misc/rbpf_256.png">
</picture>

Rust (user-space) virtual machine for eBPF

[![Build Status](https://github.com/qmonnet/rbpf/actions/workflows/test.yaml/badge.svg)](https://github.com/qmonnet/rbpf/actions/workflows/test.yaml)
[![Build status](https://ci.appveyor.com/api/projects/status/ia74coeuhxtrcvsk/branch/master?svg=true)](https://ci.appveyor.com/project/qmonnet/rbpf/branch/master)
[![Crates.io](https://img.shields.io/crates/v/rbpf.svg)](https://crates.io/crates/rbpf)

## Description

This crate contains a virtual machine for eBPF program execution. BPF, as in
_Berkeley Packet Filter_, is an assembly-like language initially developed for
BSD systems, in order to filter packets in the kernel with tools such as
tcpdump so as to avoid useless copies to user-space. It was ported to Linux,
where it evolved into eBPF (_extended_ BPF), a faster version with more
features. While BPF programs are originally intended to run in the kernel, the
virtual machine of this crate enables running it in user-space applications;
it contains an interpreter, an x86_64 JIT-compiler for eBPF programs, as well as
a disassembler.

It is based on Rich Lane's [uBPF software](https://github.com/iovisor/ubpf/),
which does nearly the same, but is written in C.

The crate is supposed to compile and run on Linux, MacOS X, and Windows,
although the JIT-compiler does not work with Windows at this time.

## License

Following the effort of the Rust language project itself in order to ease
integration with other projects, the rbpf crate is distributed under the terms
of both the MIT license and the Apache License (Version 2.0).

See
[LICENSE-APACHE](https://github.com/qmonnet/rbpf/blob/master/LICENSE-APACHE)
and [LICENSE-MIT](https://github.com/qmonnet/rbpf/blob/master/LICENSE-MIT) for
details.
