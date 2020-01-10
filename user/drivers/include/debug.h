#pragma once

#include <stdcaps.h>
#include <spec.h>

static inline void flatmk_debug_putchar(char c) {
    DebugPutchar_putchar(CAP_DEBUG_PUTCHAR, c);
}

static inline void flatmk_debug_puts(const char *s) {
    while(*s) {
        flatmk_debug_putchar(*s);
        s++;
    }
}
