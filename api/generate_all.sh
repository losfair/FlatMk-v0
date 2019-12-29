#!/bin/sh

cd `dirname $0`

cd ./flatmk-apigen || exit 1
cargo build --release || exit 1
cd .. || exit 1

# Kernel definitions.
./flatmk-apigen/target/release/flatmk-apigen -i ./spec/flatmk.toml -o ../kernel/generated/flatmk_spec.rs --language rust --generate-enums --generate-bitflags || exit 1

# Usermode bindings.
./flatmk-apigen/target/release/flatmk-apigen -i ./spec/flatmk.toml -o ../user/bindings/rust/generated/flatmk_spec.rs --language rust --generate-enums --generate-bitflags --generate-types || exit 1
./flatmk-apigen/target/release/flatmk-apigen -i ./spec/flatmk.toml -o ../user/bindings/c/flatmk_spec.h --language c --generate-enums --generate-bitflags --generate-types || exit 1

# Documentation.
./flatmk-apigen/target/release/flatmk-apigen -i ./spec/flatmk.toml -o ./book/src/usermode-interface.md --language markdown --generate-enums --generate-bitflags --generate-types || exit 1

echo "Done."
