#pragma once

#include <stdint.h>

struct FastIpcPayload {
    uint64_t data[8];
};

static __attribute__((naked)) void fastipc_read(struct FastIpcPayload *payload) {
	__asm__ volatile (
        "movq %xmm0, 0(%rdi)\n"
        "movq %xmm1, 8(%rdi)\n"
        "movq %xmm2, 16(%rdi)\n"
        "movq %xmm3, 24(%rdi)\n"
        "movq %xmm4, 32(%rdi)\n"
        "movq %xmm5, 40(%rdi)\n"
        "movq %xmm6, 48(%rdi)\n"
        "movq %xmm7, 56(%rdi)\n"
        "ret"
	);
}

static __attribute__((naked)) void fastipc_write(const struct FastIpcPayload *payload) {
	__asm__ volatile (
        "movq 0(%rdi), %xmm0\n"
        "movq 8(%rdi), %xmm1\n"
        "movq 16(%rdi), %xmm2\n"
        "movq 24(%rdi), %xmm3\n"
        "movq 32(%rdi), %xmm4\n"
        "movq 40(%rdi), %xmm5\n"
        "movq 48(%rdi), %xmm6\n"
        "movq 56(%rdi), %xmm7\n"
        "ret"
	);
}
