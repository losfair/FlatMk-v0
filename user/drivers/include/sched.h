#pragma once

#include <stdcaps.h>
#include <fastipc.h>
#include <throw.h>

static void sched_yield() {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 0;
    fastipc_write(&payload);

    while(TaskEndpoint_invoke(CAP_SCHED_YIELD) < 0);
}

static void sched_nanosleep(uint64_t ns) {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 1;
    payload.data[1] = ns;
    fastipc_write(&payload);

    while(TaskEndpoint_invoke(CAP_SCHED_YIELD) < 0);
}

static int sched_create(struct TaskEndpoint endpoint) {
    struct FastIpcPayload payload = {0};
    payload.data[0] = 0;
    fastipc_write(&payload);

    if(BasicTask_put_ipc_cap(CAP_ME, endpoint.cap, 1) < 0) flatmk_throw();
    while(TaskEndpoint_invoke(CAP_SCHED_CREATE) < 0);
    fastipc_read(&payload);
    return (int) payload.data[0];
}
