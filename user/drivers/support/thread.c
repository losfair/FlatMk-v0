#include <stddriver.h>

void flatrt_start_thread(struct BasicTask this_task, struct BasicTask task, uint64_t entry, uint64_t stack, void *tls, void *context) {
    ASSERT_OK(BasicTask_fetch_shallow_clone(this_task, task.cap));

    ASSERT_OK(
        BasicTask_set_register(task, RIP_INDEX, entry) < 0 ||
        BasicTask_set_register(task, RSP_INDEX, stack) < 0 ||
        BasicTask_set_register(task, FS_BASE_INDEX, (uint64_t) tls));

    CPtr temp_cap = libcapalloc_allocate();

    ASSERT_OK(BasicTask_fetch_task_endpoint(
        task,
        temp_cap | (((uint64_t )TaskEndpointFlags_TAGGABLE) << 48) | (1ull << 63),
        0,
        (uint64_t) context
    ));

    ASSERT_OK(sched_create(TaskEndpoint_new(temp_cap)));
    libcapalloc_release(temp_cap);
}
