#!/bin/sh

cargo xbuild --target ./x86_64-flatmk.json --release || exit 1
../../tools/elf-preloader/target/release/elf-preloader ./target/x86_64-flatmk/release/init ../../kernel/generated/user_init || exit 1
echo "Build completed."