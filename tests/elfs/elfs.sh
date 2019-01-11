#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

LLVM_DIR=../../../solana/sdk/bpf/llvm-native/bin/

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o noop.o -c noop.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o noop.so noop.o
rm noop.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o unresolved_helper.o -c unresolved_helper.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o unresolved_helper.so unresolved_helper.o
rm unresolved_helper.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o entrypoint.o -c entrypoint.c
"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o helper.o -c helper.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint -o multiple_file.so entrypoint.o helper.o
rm entrypoint.o
rm helper.o
