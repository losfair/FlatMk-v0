#pragma once

#include <spec.h>
#include <stdcaps.h>
#include <debug.h>
#include <fastipc.h>
#include <sched.h>
#include <throw.h>
#include <arch.h>
#include <stddef.h>

#define FS_BASE_INDEX 58
#define GS_BASE_INDEX 59
#define RIP_INDEX 16
#define RSP_INDEX 7

#define ASSERT_OK(x) if((x) < 0) { flatmk_throw(); }

extern unsigned char FLATRT_DRIVER_GLOBAL_TLS[4096 * 16];

//void *__copy_tls(unsigned char *mem);

static void flatmk_set_fs_base(uint64_t value) {
    ASSERT_OK(BasicTask_set_register(CAP_ME, FS_BASE_INDEX, value));
}

static void start_thread(struct BasicTask task, uint64_t entry, uint64_t stack, void *tls, void *context) {
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, task.cap));

    ASSERT_OK(
        BasicTask_set_register(task, RIP_INDEX, entry) < 0 ||
        BasicTask_set_register(task, RSP_INDEX, stack) < 0 ||
        BasicTask_set_register(task, FS_BASE_INDEX, (uint64_t) tls));

    ASSERT_OK(BasicTask_fetch_task_endpoint(
        task,
        CAP_BUFFER | (((uint64_t )TaskEndpointFlags_TAGGABLE) << 48) | (1ull << 63),
        0,
        (uint64_t) context
    ));

    ASSERT_OK(sched_create(TaskEndpoint_new(CAP_BUFFER)));
}
