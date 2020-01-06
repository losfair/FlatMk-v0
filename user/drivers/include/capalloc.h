#pragma once

#include <spec.h>

void libcapalloc_init(CPtr capset, uint64_t dynamic_base);
CPtr libcapalloc_allocate();
void libcapalloc_release(CPtr cap);
