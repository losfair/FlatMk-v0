#include <stddriver.h>
#include "syscalls.h"
#include "linux_task.h"
#include <stdio.h>

void dispatch_syscall(struct LinuxTask *task, struct TaskRegisters *registers) {
    char buf[512];

    switch(registers->rax) {
        default: {
            sprintf(buf, "dispatch_syscall: Unknown linux syscall index: %llu\n", registers->rax);
            flatmk_debug_puts(buf);

            registers->rax = (uint64_t) -1ll;
            
            break;
        }
    }

    ASSERT_OK(BasicTask_set_all_registers(task->managed, (uint64_t) registers, sizeof(struct TaskRegisters)));
    BasicTask_ipc_return(task->host);
}
