# Security Policy

rbpf is a small project created as a way to experiment with Rust and eBPF, and
developed on a best-effort basis. **It is not targeted at running in
production**: use it at your own risk.

This document describes what rbpf does and does not try to protect against, and
how to report issues that fall within that scope.

## Supported Versions

Only the latest released version of the crate receives security fixes, through
the `main` branch. Fixes are not backported to older releases.

## Reporting a Vulnerability

If you suspect you've found a vulnerability, you can send an email to the
maintainer at <rbpf@qmon.net>, with:

- the affected version(s) and execution mode(s) (interpreter, JIT, Cranelift),
- a description of the issue and of its impact,
- a reproducer (eBPF program and host code), if possible,
- a proposed fix, if you have one.

The maintainer aims to respond within a reasonable time, but does not provide
any guarantee, as the project is maintained in spare time.

## Security Model

### Trust boundaries

rbpf runs eBPF programs on behalf of a host application. The model is as
follows:

- **The host application is trusted.** This includes the Rust code embedding
  rbpf, the helper functions it registers, the custom verifier it may install,
  the location and size of the memory buffers it passes to the VM, and the
  memory ranges it registers with `register_allowed_memory()`.
- **The eBPF program may be untrusted**, but only when it runs in the
  interpreter (see below).
- **The contents of the memory areas passed to the program may be untrusted**
  (for example, network packets). The interpreter's memory checks do not depend
  on these contents: every access is validated at runtime, including accesses
  through pointers that the program reads from the metadata buffer. Whether the
  program itself handles malicious data correctly, however, is a matter for the
  program, not for rbpf.

### What the interpreter aims to guarantee

When running a program with `execute_program()`, the interpreter aims to
ensure that:

- Every load and store performed by the program lies entirely within one of the
  following regions: the packet data (`mem`), the metadata buffer (`mbuff`),
  the program's stack, or one of the ranges registered with
  `register_allowed_memory()`.
- Invalid programs or invalid memory accesses cause `execute_program()` to
  return an error rather than panic, crash, or read or write host memory
  outside of the above regions, provided the default verifier, or one at least
  as strict, is in use.
- The depth of eBPF-to-eBPF function calls is bounded.

A program that manages to break one of these properties when run in the
interpreter is a vulnerability in rbpf, and should be reported as described
above.

### What rbpf does not guarantee

The following are **outside of the scope** of rbpf's security model. Issues in
these areas are regular bugs or limitations, and can be reported through public
issues.

- **The x86_64 JIT compiler performs no memory checks.** JIT-compiled programs
  can read and write arbitrary memory of the host process. This is why
  `execute_program_jit()` is an `unsafe` function: only run trusted programs
  with the JIT.
- **The Cranelift backend** inserts bounds checks for packet data, metadata
  buffer and stack accesses, but it does not support memory ranges registered
  with `register_allowed_memory()`. Out-of-bounds accesses cause the process to
  abort rather than returning an error. It should not be relied upon to run
  untrusted programs.
- **Termination is not guaranteed.** The default verifier only rejects trivial
  infinite loops. There is no limit on the number of instructions executed, so
  a program may loop forever. Hosts running untrusted programs should enforce
  their own time limits (for example, by running the VM in a separate thread or
  process).
- **The default verifier is minimal.** It checks the program's structure
  (instruction encoding, jump targets, register numbers, final `EXIT`), but it
  is in no way equivalent to the Linux kernel's verifier. It does not track
  register types or values, and it does not prove memory safety: the runtime
  checks of the interpreter do.
- **Helper functions are trusted.** They receive raw 64-bit values from the
  program. Validating these values (in particular, any value used as a pointer
  or a length) is the responsibility of the host application. A memory safety
  issue in a host-provided helper is not a vulnerability in rbpf.
- **Memory ranges registered with `register_allowed_memory()` are fully
  accessible** to the program, for both reads and writes. The host is
  responsible for registering only ranges that are valid for the duration of
  the program's execution, and that the program is allowed to modify.
- **Side channels** (timing attacks, speculative execution such as Spectre)
  are not mitigated.
- **Resource exhaustion** in the host (for example, through helpers called
  repeatedly) is not prevented.

### Recommendations for running untrusted programs

rbpf is not a hardened sandbox. If you run eBPF programs from untrusted
sources:

- use the interpreter only, not the JIT or Cranelift backends;
- keep the set of helpers and registered memory ranges minimal, and validate
  all helper arguments;
- enforce a time limit on program execution;
- consider adding OS-level isolation (separate process, seccomp, containers)
  around the VM.
