all:
	musl-gcc -nostartfiles -static -O2 \
		-fno-stack-protector \
		-I../include -I../../bindings/c \
		-mgeneral-regs-only \
		-o ../bin/input.driver \
		../support/*.c main.c \
		-L../libflatrt/target/x86_64-flatmk-early/release \
		-lflatrt
