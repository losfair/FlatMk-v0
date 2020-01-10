#include <stddriver.h>
#include <stdio.h>
#include "echo_elf.h"
#include "ipc_return_elf.h"

struct TaskEndpoint CAP_INIT_RET = { 0x10 };
struct BasicTask CAP_THREAD_TEST = { 0x11 };
struct TaskEndpoint CAP_THREAD_TEST_ENDPOINT = { 0x12 };

uint8_t __test_thread_stack[4096];

void *temp_map_base = (void *) 0x300000000000ull;

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

    sprintf(buf, "Benchmark: Softuser enter/leave\n");
    flatmk_debug_puts(buf);

    {
        uint32_t softuser_entry_addr = 0;
        ASSERT_OK(libelfloader_load_softuser(
            ECHO_ELF_BYTES,
            sizeof(ECHO_ELF_BYTES),
            (uint64_t) temp_map_base,
            CAP_RPT.cap,
            &softuser_entry_addr
        ));

        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 10000000; i++) {
            softuser_enter(softuser_entry_addr);
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 10000000);
        flatmk_debug_puts(buf);
    }

    flatmk_debug_puts("Benchmark: IPC w/o PT switch to softuser\n");

    {
        uint32_t softuser_entry_addr = 0;
        ASSERT_OK(libelfloader_load_softuser(
            IPC_RETURN_ELF_BYTES,
            sizeof(IPC_RETURN_ELF_BYTES),
            (uint64_t) temp_map_base,
            CAP_RPT.cap,
            &softuser_entry_addr
        ));

        ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, CAP_THREAD_TEST.cap));
        softuser_remote_enter(CAP_THREAD_TEST);

        ASSERT_OK(BasicTask_fetch_task_endpoint(CAP_THREAD_TEST, CAP_THREAD_TEST_ENDPOINT.cap, (uint64_t) softuser_entry_addr, CAP_THREAD_TEST.cap));

        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 2000000; i++) {
            ASSERT_OK(TaskEndpoint_invoke(CAP_THREAD_TEST_ENDPOINT));
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 2000000);
        flatmk_debug_puts(buf);
    }

    flatmk_debug_puts("Benchmark: IPC w/ PT switch to softuser\n");

    {
        uint32_t softuser_entry_addr = 0;
        struct RootPageTable new_rpt = { libcapalloc_allocate() };
        ASSERT_OK(BasicTask_make_root_page_table(CAP_ME, new_rpt.cap));

        ASSERT_OK(libelfloader_load_softuser(
            IPC_RETURN_ELF_BYTES,
            sizeof(IPC_RETURN_ELF_BYTES),
            (uint64_t) temp_map_base,
            new_rpt.cap,
            &softuser_entry_addr
        ));

        ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, CAP_THREAD_TEST.cap));
        softuser_remote_enter(CAP_THREAD_TEST);

        ASSERT_OK(BasicTask_put_root_page_table(CAP_THREAD_TEST, new_rpt));
        ASSERT_OK(BasicTask_fetch_task_endpoint(CAP_THREAD_TEST, CAP_THREAD_TEST_ENDPOINT.cap, (uint64_t) softuser_entry_addr, CAP_THREAD_TEST.cap));

        uint64_t start = __builtin_ia32_rdtsc();
        for(int i = 0; i < 2000000; i++) {
            ASSERT_OK(TaskEndpoint_invoke(CAP_THREAD_TEST_ENDPOINT));
        }
        uint64_t end = __builtin_ia32_rdtsc();
        sprintf(buf, "benchmark: %lu cycles per op\n", (end - start) / 2000000);
        flatmk_debug_puts(buf);

        libcapalloc_release(new_rpt.cap);
    }

    ASSERT_OK(TaskEndpoint_invoke(CAP_INIT_RET));
    flatmk_throw();
}

