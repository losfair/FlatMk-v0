#pragma once

#include <stdcaps.h>
#include <fastipc.h>
#include <throw.h>

struct SoftuserRegisters {
    uint32_t regs[32];
};

static void softuser_enter(uint32_t pc) {
    if(TrivialSyscallEntry_softuser_enter(CAP_TRIVIAL_SYSCALL, pc) < 0) flatmk_throw();
}

static void softuser_leave() {
    if(TrivialSyscallEntry_softuser_leave(CAP_TRIVIAL_SYSCALL) < 0) flatmk_throw();
}

void softuser_remote_enter(struct BasicTask task);