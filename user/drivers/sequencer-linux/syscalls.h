#pragma once

#include <stddriver.h>
#include "linux_task.h"

void dispatch_syscall(struct LinuxTask *task, struct TaskRegisters *registers);
