#pragma once

#include <spec.h>

int flatrt_shmem_create(struct BasicTask this_task, uint64_t size, struct TaskEndpoint out_endpoint);
int flatrt_shmem_map(struct BasicTask this_task, struct TaskEndpoint endpoint, void *local_addr, uint64_t size);
