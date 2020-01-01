#pragma once

#include <stdcaps.h>
#include <fastipc.h>
#include <throw.h>

static void sched_yield() {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 0;
    fastipc_write(&payload);

    if(TaskEndpoint_invoke(CAP_SCHED_YIELD) < 0) flatmk_throw();
}

static void sched_nanosleep(uint64_t ns) {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 1;
    payload.data[1] = ns;
    fastipc_write(&payload);

    if(TaskEndpoint_invoke(CAP_SCHED_YIELD) < 0) flatmk_throw();
}

static uint64_t sched_read_tsc_freq() {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 2;
    fastipc_write(&payload);

    if(TaskEndpoint_invoke(CAP_SCHED_YIELD) < 0) flatmk_throw();
    fastipc_read(&payload);
    if((int64_t) payload.data[0] < 0) flatmk_throw();
    return payload.data[0];
}

static int sched_create(struct TaskEndpoint endpoint) {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 0;
    fastipc_write(&payload);

    if(BasicTask_put_ipc_cap(CAP_ME, endpoint.cap, 1) < 0) flatmk_throw();
    if(TaskEndpoint_invoke(CAP_SCHED_CREATE) < 0) flatmk_throw();
    fastipc_read(&payload);
    return (int) payload.data[0];
}
