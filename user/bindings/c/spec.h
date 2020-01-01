#pragma once

#include <stdint.h>

typedef uint64_t CPtr;
static __attribute__((naked)) int64_t cptr_invoke(
	CPtr cptr,
	int64_t p0,
	int64_t p1,
	int64_t p2,
	int64_t p3
) {
	__asm__ volatile (
		"xor %eax, %eax\n"
		"mov %rcx, %r10\n"
		"syscall\n"
		"ret\n"
	);
}

#include "./flatmk_spec.h"
