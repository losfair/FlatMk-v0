#pragma once

#include <spec.h>

int64_t libelfloader_load_softuser(
    const uint8_t *image_base,
    uint64_t image_len,
    uint64_t temp_base,
    CPtr rpt,
    uint32_t *out_entry_address
);
