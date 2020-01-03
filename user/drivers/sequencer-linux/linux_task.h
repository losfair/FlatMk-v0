#pragma once

#include <stddriver.h>
#include "mm.h"
#include "fd.h"

#define LT_HEAP_BASE 0x1000000ull
#define LT_MMAP_BASE 0x20000000ull
#define LT_STACK_END 0x80000000ull
#define LT_STACK_SIZE 1048576ull
#define LT_STACK_START (LT_STACK_END - LT_STACK_SIZE)
#define LT_SHADOW_MAP_SIZE 0x100000000
#define LT_FD_TABLE_SIZE 32


struct LinuxTask {
    void *host_stack;
    void *host_stack_end;
    struct BasicTask host;
    struct BasicTask managed;
    struct CapabilitySet managed_capset; // should be empty
    struct RootPageTable managed_rpt;
    struct TaskEndpoint managed_fault_to_host;
    struct TaskEndpoint managed_sched;
    struct LinuxMmState *mm;
    uint64_t shadow_map_base;
    int terminated;
    uint64_t current_brk;
    struct FileDescriptor fds[LT_FD_TABLE_SIZE];
};

void linux_task_start(const uint8_t *image, uint64_t image_len);
void linux_task_drop(struct LinuxTask *t);

void * acquire_umem(struct LinuxTask *lt, uint64_t uaddr, uint64_t size, int write);
