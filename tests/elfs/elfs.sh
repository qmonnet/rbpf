#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

LLVM_DIR=../../../solana/sdk/bpf/llvm-native/bin/

"$LLVM_DIR"clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -fPIC -o noop.bc -c noop.c
"$LLVM_DIR"llc -march=bpf -filetype=obj -o noop.o noop.bc
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o noop.so noop.o
rm noop.bc
rm noop.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -fPIC -o unresolved_helper.bc -c unresolved_helper.c
"$LLVM_DIR"llc -march=bpf -filetype=obj -o unresolved_helper.o unresolved_helper.bc
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o unresolved_helper.so unresolved_helper.o
rm unresolved_helper.bc
rm unresolved_helper.o
