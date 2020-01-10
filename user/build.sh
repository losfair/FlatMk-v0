#!/bin/bash

#cd `$(dirname $0)` || exit 1

echo "Building flatrt-shmem"
cd early/flatrt-shmem || exit 1
cargo xbuild --target ../x86_64-flatmk-early.json --release || exit 1

echo "Building softuser binary: echo"
cd ../../softuser/echo || exit 1
cargo xbuild --target ../riscv32-flatmk-softuser.json --release || exit 1
python3 ../../../tools/gen_bytes.py ./target/riscv32-flatmk-softuser/release/echo ECHO_ELF_BYTES > ../../drivers/benchmark/echo_elf.h || exit 1

echo "Building softuser binary: ipc-return"
cd ../ipc-return || exit 1
cargo xbuild --target ../riscv32-flatmk-softuser.json --release || exit 1
python3 ../../../tools/gen_bytes.py ./target/riscv32-flatmk-softuser/release/ipc-return IPC_RETURN_ELF_BYTES > ../../drivers/benchmark/ipc_return_elf.h || exit 1

echo "Building driver library: libflatrt"
cd ../../drivers/libflatrt || exit 1
cargo xbuild --target ../../early/x86_64-flatmk-early.json --release || exit 1

echo "Building driver: vga"
cd ../vga || exit 1
make || exit 1

echo "Building driver: input"
cd ../input || exit 1
make || exit 1

echo "Building driver: gclock"
cd ../gclock || exit 1
make || exit 1

echo "Building driver: benchmark"
cd ../benchmark || exit 1
make || exit 1

echo "Building linux init for sequencer-linux"
cd ../sequencer-linux/linux || exit 1
#gcc -static -O2 -o ./generated/init.elf ./init.c || exit 1
python3 ./gen_bytes.py ./generated/init.elf > ./generated/init.h || exit 1

echo "Building driver: sequencer-linux"
cd .. || exit 1
make || exit 1

echo "Building flatrt-init"
cd ../../early/flatrt-init || exit 1
cargo xbuild --target ../x86_64-flatmk-early.json --release || exit 1

echo "Building elf-preloader"
pushd . || exit 1
cd ../../../tools/elf-preloader || exit 1
cargo build --release || exit 1
popd || exit 1

echo "Preloading init"
../../../tools/elf-preloader/target/release/elf-preloader ./target/x86_64-flatmk-early/release/flatrt-init ../../../kernel/generated/user_init || exit 1

echo "Build completed."
