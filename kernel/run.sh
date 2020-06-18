#!/bin/sh

qemu-system-x86_64 \
    -enable-kvm \
    -drive format=raw,file=target/x86_64-unknown-none/release/bootimage-kernel.bin \
    -serial stdio