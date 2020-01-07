#pragma once

#include <stdatomic.h>

struct ReentrancyGuard {
    uint8_t value;
};

static inline int reentrancy_guard_try_lock(struct ReentrancyGuard *g) {
    uint8_t prev = 0;
    if(!atomic_compare_exchange_strong(&g->value, &prev, 1)) {
        return 0;
    } else {
        return 1;
    }
}

static inline void reentrancy_guard_unlock(struct ReentrancyGuard *g) {
    atomic_store(&g->value, 0);
}
