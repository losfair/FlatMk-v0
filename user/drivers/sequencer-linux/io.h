#pragma once

#include <sys/uio.h>
#include "fd.h"
#include "linux_task.h"

extern struct FdOps ops_stdout;
extern struct FdOps ops_stderr;
extern struct FdOps ops_vga;
extern struct FdOps ops_kbd;

int64_t do_openat(struct LinuxTask *lt, const char *path);