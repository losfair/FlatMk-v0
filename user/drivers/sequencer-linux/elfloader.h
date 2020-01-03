#pragma once

#include <stdint.h>
#include <spec.h>

#include "mm.h"

int64_t libelfloader_load_and_apply(
    struct LinuxMmState *mm,
    const uint8_t *image_base,
    uint64_t image_len,
    uint64_t temp_base,
    CPtr this_rpt,
    CPtr task,
    uint64_t *out_entry_address
);

int64_t libelfloader_build_and_apply_stack(
    uint64_t start,
    uint64_t size,
    CPtr rpt,
    CPtr task
);
