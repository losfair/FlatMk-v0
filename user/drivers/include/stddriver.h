#pragma once

#include <spec.h>
#include <stdcaps.h>
#include <debug.h>
#include <fastipc.h>
#include <sched.h>
#include <throw.h>
#include <arch.h>
#include <shmem.h>
#include <capalloc.h>
#include <allocator.h>
#include <reentrancy_guard.h>
#include <stddef.h>

#define FS_BASE_INDEX 58
#define GS_BASE_INDEX 59
#define RIP_INDEX 16
#define RSP_INDEX 7

#define ASSERT_OK(x) if((x) < 0) { flatmk_throw(); }

extern unsigned char FLATRT_DRIVER_GLOBAL_TLS[4096 * 16];

//void *__copy_tls(unsigned char *mem);

static inline void flatmk_set_fs_base(uint64_t value) {
    ASSERT_OK(BasicTask_set_register(CAP_ME, FS_BASE_INDEX, value));
}

void flatrt_start_thread(struct BasicTask this_task, struct BasicTask task, uint64_t entry, uint64_t stack, void *tls, void *context);
