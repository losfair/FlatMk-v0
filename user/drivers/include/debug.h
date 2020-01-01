#pragma once

#include <stdcaps.h>
#include <spec.h>

static void flatmk_debug_putchar(char c) {
    DebugPutchar_putchar(CAP_DEBUG_PUTCHAR, c);
}

static void flatmk_debug_puts(const char *s) {
    while(*s) {
        flatmk_debug_putchar(*s);
        s++;
    }
}
