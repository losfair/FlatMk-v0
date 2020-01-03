all:
	musl-gcc -nostartfiles -static -O2 \
		-I../include -I../../bindings/c \
		-mgeneral-regs-only \
		-o ../bin/sequencer-linux.driver \
		../support/*.c ./*.c \
		-L../libflatrt/target/x86_64-flatmk-early/release \
		-lflatrt