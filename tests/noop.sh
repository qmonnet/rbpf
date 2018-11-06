#!/bin/bash -ex

# Requires LLVM 7.x or newer
#http://releases.llvm.org/download.html

/usr/local/opt/llvm/bin/clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -o noop.bc -c noop.c
/usr/local/opt/llvm/bin/llc -march=bpf -filetype=obj -o noop.o noop.bc
rm noop.bc

/usr/local/opt/llvm/bin/clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -o noop_multiple_text.bc -c noop.c
/usr/local/opt/llvm/bin/llc -march=bpf -filetype=obj -function-sections -o noop_multiple_text.o noop_multiple_text.bc
rm noop_multiple_text.bc

