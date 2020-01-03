#pragma once

#include <sys/uio.h>
#include <stddriver.h>

struct FileDescriptor;
struct LinuxTask;

struct FdOps {
    void * (*mmap)(struct LinuxTask *lt, struct FileDescriptor *fd, void * addr, uint64_t length, int linux_prot, int linux_flags, uint64_t offset);
    int64_t (*readv)(struct LinuxTask *lt, struct FileDescriptor *fd, const struct iovec *iov, int iovcnt);
    int64_t (*writev)(struct LinuxTask *lt, struct FileDescriptor *fd, const struct iovec *iov, int iovcnt);
    void (*drop)(struct LinuxTask *lt, struct FileDescriptor *fd);
};

struct FileDescriptor {
    const struct FdOps *ops;
};
