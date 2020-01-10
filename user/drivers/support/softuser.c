#include <stddriver.h>

static uint32_t rvcode[] = {
    0x00000073, // ecall
    0x00100073  // ebreak
};

static void softuser_remote_enter_ll_entry() {
    if((uint64_t) rvcode > (uint64_t) (uint32_t) -1) {
        flatmk_debug_puts("softuser_remote_enter_ll_entry: rvcode is not in the first 32-bit address space.");
        flatmk_throw();
    }
    softuser_enter((uint64_t) rvcode);
    flatmk_throw();
}

void softuser_remote_enter(struct BasicTask task) {
    uint8_t stack[512];
    struct TaskEndpoint endpoint = { libcapalloc_allocate() };

    struct SoftuserRegisters regs = {};
    regs.regs[10] = task.cap;
    regs.regs[11] = task.cap >> 32;
    regs.regs[12] = BasicTaskRequest_IpcReturn;
    ASSERT_OK(BasicTask_set_all_softuser_registers(task, (uint64_t) &regs, sizeof(regs)));

    ASSERT_OK(BasicTask_set_register(task, RSP_INDEX, (uint64_t) stack + sizeof(stack)));
    ASSERT_OK(BasicTask_fetch_task_endpoint(task, endpoint.cap, (uint64_t) softuser_remote_enter_ll_entry, 0));
    ASSERT_OK(TaskEndpoint_invoke(endpoint));
    libcapalloc_release(endpoint.cap);
}