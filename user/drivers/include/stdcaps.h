#pragma once

#include <spec.h>

static struct BasicTask CAP_ME = { 0 };
static struct DebugPutchar CAP_DEBUG_PUTCHAR = { 1 };
static struct TaskEndpoint CAP_SCHED_CREATE = { 2 };
static struct TaskEndpoint CAP_SCHED_YIELD = { 3 };
static struct TaskEndpoint CAP_SHMEM_CREATE = { 4 };

// We create these caps in init function
static struct CapabilitySet CAP_CAPSET = { 5 };
static struct RootPageTable CAP_RPT = { 6 };

static CPtr CAP_BUFFER = { 15 };
