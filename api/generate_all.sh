#!/bin/sh

cd `dirname $0`

cd ./flatmk-apigen || exit 1
cargo build --release || exit 1
cd .. || exit 1

./flatmk-apigen/target/release/flatmk-apigen -i ./spec/flatmk.toml -o ../kernel/generated/flatmk_spec.rs --generate-enums || exit 1

echo "Done."
