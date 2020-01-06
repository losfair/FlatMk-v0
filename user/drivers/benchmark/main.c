#include <stddriver.h>
#include <stdio.h>

struct TaskEndpoint CAP_INIT_RET = { 0x10 };
struct BasicTask CAP_THREAD_TEST = { 0x11 };
struct TaskEndpoint CAP_THREAD_TEST_ENDPOINT = { 0x12 };

uint8_t __test_thread_stack[4096];

void test_thread_entry() {
    BasicTask_ipc_return(CAP_THREAD_TEST);
    flatmk_throw();
}

void __attribute__((naked)) __test_thread_entry() {
    __asm__ volatile(
        "lea __test_thread_stack, %rsp\n"
        "add $4096, %rsp\n"
        "jmp test_thread_entry\n"
    );
}

void main() {
    char buf[256];

    ASSERT_OK(BasicTask_fetch_ipc_cap(CAP_ME, CAP_INIT_RET.cap, 0));

    sprintf(buf, "Benchmark: IPC w/o PT switch\n");
    flatmk_debug_puts(buf);

    {
        ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, CAP_THREAD_TEST.cap));
        ASSERT_OK(BasicTask_fetch_task_endpoint(CAP_THREAD_TEST, CAP_THREAD_TEST_ENDPOINT.cap, (uint64_t) __test_thread_entry, 0));

        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 1000000; i++) {
            ASSERT_OK(TaskEndpoint_invoke(CAP_THREAD_TEST_ENDPOINT));
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 1000000);
        flatmk_debug_puts(buf);
    }

    sprintf(buf, "Benchmark: IPC w/ PT switch to SHMEM daemon (CAP_TRANSFER)\n");
    flatmk_debug_puts(buf);

    {
        struct FastIpcPayload payload = {0};
        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 1000000; i++) {
            payload.data[0] = 0xffff;
            fastipc_write(&payload);
            ASSERT_OK(TaskEndpoint_invoke(CAP_SHMEM_CREATE));
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 1000000);
        flatmk_debug_puts(buf);
    }

    sprintf(buf, "Benchmark: Scheduler yield\n");
    flatmk_debug_puts(buf);

    {
        struct FastIpcPayload payload = {0};
        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 1000000; i++) {
            sched_yield();
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 1000000);
        flatmk_debug_puts(buf);
    }

    ASSERT_OK(TaskEndpoint_invoke(CAP_INIT_RET));
    flatmk_throw();
}

