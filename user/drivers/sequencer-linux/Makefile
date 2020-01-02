all:
	musl-gcc -nostartfiles -static -O2 \
		-I../include -I../../bindings/c \
		-mgeneral-regs-only \
		-o ../bin/sequencer-linux.driver \
		../support/*.c main.c syscalls.c \
		-L../libelfloader/target/x86_64-flatmk-early/release -lelfloader
