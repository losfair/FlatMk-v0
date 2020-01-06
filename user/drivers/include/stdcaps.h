#pragma once

#include <spec.h>

static const struct BasicTask CAP_ME = { 0 };
static const struct DebugPutchar CAP_DEBUG_PUTCHAR = { 1 };

static const struct TaskEndpoint CAP_SHMEM_CREATE = { 4 };

// We create these caps in init function
static const struct CapabilitySet CAP_CAPSET = { 5 };
static const struct RootPageTable CAP_RPT = { 6 };

static const CPtr CAP_BUFFER = { 15 };

static const uint64_t CAP_DYNAMIC_BASE = 0xf0000000;

static const struct TrivialSyscallEntry CAP_TRIVIAL_SYSCALL = { (uint64_t) -1ll };
