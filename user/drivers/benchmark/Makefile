all:
	musl-gcc -nostartfiles -static -O2 \
		-I../include -I../../bindings/c \
		-mgeneral-regs-only \
		-o ../bin/benchmark.driver \
		../support/*.c main.c
