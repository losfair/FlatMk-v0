all:
	musl-gcc -nostartfiles -static -O2 \
		-I../include -I../../bindings/c \
		-mgeneral-regs-only \
		-o ../bin/gclock.driver \
		../support/*.c main.c
