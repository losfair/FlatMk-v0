#!/bin/bash

#cd `$(dirname $0)` || exit 1

echo "Building flatrt-schduler"
cd early/flatrt-scheduler
cargo xbuild --target ../x86_64-flatmk-early.json --release || exit 1

echo "Building flatrt-init"
cd ../flatrt-init || exit 1
cargo xbuild --target ../x86_64-flatmk-early.json --release || exit 1

echo "Building elf-preloader"
pushd . || exit 1
cd ../../../tools/elf-preloader || exit 1
cargo build --release || exit 1
popd || exit 1

echo "Preloading init"
../../../tools/elf-preloader/target/release/elf-preloader ./target/x86_64-flatmk-early/release/flatrt-init ../../../kernel/generated/user_init || exit 1

echo "Build completed."
