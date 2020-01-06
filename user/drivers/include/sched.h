#pragma once

#include <stdcaps.h>
#include <fastipc.h>
#include <throw.h>

static void sched_yield() {
    if(TrivialSyscallEntry_sched_yield(CAP_TRIVIAL_SYSCALL) < 0) flatmk_throw();
}

static void sched_nanosleep(uint64_t ns) {
    if(TrivialSyscallEntry_sched_nanosleep(CAP_TRIVIAL_SYSCALL, ns) < 0) flatmk_throw();
}

static int sched_create(struct TaskEndpoint endpoint) {
    return TrivialSyscallEntry_sched_submit(CAP_TRIVIAL_SYSCALL, endpoint);
}
