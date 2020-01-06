#pragma once

#include <spec.h>

static const uint64_t DYNAMIC_ALLOC_BASE = 0xa0000000;

void libmalloc_init(uint64_t heap_start, CPtr rpt);
