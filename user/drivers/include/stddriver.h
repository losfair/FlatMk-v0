#pragma once

#include <spec.h>
#include <stdcaps.h>
#include <debug.h>
#include <fastipc.h>
#include <sched.h>
#include <throw.h>

#define FS_BASE_INDEX 58
#define GS_BASE_INDEX 59
#define RIP_INDEX 16
#define RSP_INDEX 7

//void *__copy_tls(unsigned char *mem);

static void flatmk_set_fs_base(uint64_t value) {
    if(BasicTask_set_register(CAP_ME, FS_BASE_INDEX, value) != 0) flatmk_throw();
}

static void start_thread(struct BasicTask task, uint64_t entry, uint64_t stack, void *tls) {
    if(BasicTask_fetch_shallow_clone(CAP_ME, task.cap) < 0) flatmk_throw();

    if(
        BasicTask_set_register(task, RIP_INDEX, entry) < 0 ||
        BasicTask_set_register(task, RSP_INDEX, stack) < 0 ||
        BasicTask_set_register(task, FS_BASE_INDEX, (uint64_t) tls) < 0
    ) {
        flatmk_throw();
    }

    if(BasicTask_fetch_task_endpoint(
        task,
        CAP_BUFFER | (((uint64_t )TaskEndpointFlags_TAGGABLE) << 48) | (1ull << 63),
        0,
        0
    ) < 0) {
        flatmk_throw();
    }

    if(sched_create(TaskEndpoint_new(CAP_BUFFER)) < 0) {
        flatmk_throw();
    }
}
