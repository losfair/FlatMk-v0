#!/bin/sh

cd $(dirname $0) || exit 1

python3 ./generate_interrupts_idt.py > ../generated/interrupts_idt.rs || exit 1
python3 ./generate_interrupts_impl.py > ../generated/interrupts_impl.rs || exit 1
