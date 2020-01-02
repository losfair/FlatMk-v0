#pragma once

#include <stddriver.h>

struct LinuxTask {
    void *host_stack;
    void *host_stack_end;
    struct BasicTask host;
    struct BasicTask managed;
    struct CapabilitySet managed_capset; // should be empty
    struct RootPageTable managed_rpt;
    struct TaskEndpoint managed_fault_to_host;
    struct TaskEndpoint managed_sched;
    uint64_t shadow_map_base;
    int terminated;
};

void linux_task_start(const uint8_t *image, uint64_t image_len);
void linux_task_drop(struct LinuxTask *t);
