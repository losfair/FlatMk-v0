#include <stddriver.h>

int flatrt_shmem_create(struct BasicTask this_task, uint64_t size, struct TaskEndpoint out_endpoint) {
    struct FastIpcPayload payload = {0};

    // Create
    payload.data[0] = 0;

    // Size
    payload.data[1] = size;

    fastipc_write(&payload);
    while(TaskEndpoint_invoke(CAP_SHMEM_CREATE) < 0) sched_yield();
    fastipc_read(&payload);

    if((int64_t) payload.data[0] < 0) {
        return -1;
    }

    if(BasicTask_fetch_ipc_cap(this_task, out_endpoint.cap, 1) < 0) {
        flatmk_throw();
    }

    return 0;
}

int flatrt_shmem_map(struct BasicTask this_task, struct TaskEndpoint endpoint, void *local_addr, uint64_t size) {
    struct FastIpcPayload payload = {0};

    payload.data[0] = 0;
    payload.data[1] = (uint64_t) local_addr;
    payload.data[2] = size;

    CPtr temp_cap = libcapalloc_allocate();
    // Put local page table.
    if(CapabilitySet_clone_cap(CAP_CAPSET, CAP_RPT.cap, temp_cap) < 0) flatmk_throw();
    if(BasicTask_put_ipc_cap(this_task, temp_cap, 1) < 0) flatmk_throw();
    libcapalloc_release(temp_cap);

    fastipc_write(&payload);
    while(TaskEndpoint_invoke(endpoint) < 0) sched_yield();
    fastipc_read(&payload);

    if((int64_t) payload.data[0] < 0) {
        return -1;
    }

    return 0;
}
