#pragma once

static __attribute__((noreturn, always_inline)) void flatmk_throw() {
    __asm__ volatile ("ud2");
    while(1) {}
}
