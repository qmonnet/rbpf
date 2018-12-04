#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

<path to custom Solana llvm>/clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -fPIC -o noop.bc -c noop.c
<path to custom Solana llvm>/llc -march=bpf -filetype=obj -o noop.o noop.bc
<path to custom Solana llvm>/ld.lld -z notext -shared --Bdynamic -o noop.so noop.o
rm noop.bc
rm noop.o
