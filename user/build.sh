#!/bin/bash

#cd `$(dirname $0)` || exit 1

echo "Building scheduler"
cd scheduler || exit 1
cargo xbuild --target ../x86_64-flatmk.json --release || exit 1

echo "Building init"
cd ../init || exit 1
cargo xbuild --target ../x86_64-flatmk.json --release || exit 1

echo "Building elf-preloader"
pushd . || exit 1
cd ../../tools/elf-preloader || exit 1
cargo build --release || exit 1
popd || exit 1

echo "Preloading init"
../../tools/elf-preloader/target/release/elf-preloader ./target/x86_64-flatmk/release/init ../../kernel/generated/user_init || exit 1

echo "Build completed."
