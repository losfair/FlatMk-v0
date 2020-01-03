#pragma once

#include <spec.h>

struct LinuxMmState {
    int _unused;
};

struct LinuxMmState * linux_mm_new(CPtr managed_task, uint64_t shadow_base, uint64_t shadow_limit);
int linux_mm_validate_target_va(const struct LinuxMmState *mm, uint64_t va, uint64_t *out_prot);
int64_t linux_mm_insert_region(struct LinuxMmState *mm, uint64_t start, uint64_t end, uint64_t prot);
