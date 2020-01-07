#include "io.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fastipc.h>

static int64_t console_writev(struct LinuxTask *lt, struct FileDescriptor *fd, const struct iovec *iov, int iovcnt) {
    uint64_t count = 0;
    for(int i = 0; i < iovcnt; i++) {
        const struct iovec *v = &iov[i];
        const uint8_t *str = acquire_umem(lt, (uint64_t) v->iov_base, v->iov_len, 0);
        if(!str) {
            flatmk_debug_puts("invalid ref\n");
            return -1;
        }
        count += v->iov_len;
        for(uint64_t i = 0; i < v->iov_len; i++) {
            ASSERT_OK(DebugPutchar_putchar(CAP_DEBUG_PUTCHAR, str[i]));
        }
    }
    return count;
}

static int64_t kbd_readv(struct LinuxTask *lt, struct FileDescriptor *fd, const struct iovec *iov, int iovcnt) {
    uint64_t count = 0;
    for(int i = 0; i < iovcnt; i++) {
        const struct iovec *v = &iov[i];
        uint8_t *str = acquire_umem(lt, (uint64_t) v->iov_base, v->iov_len, 1); // writable
        if(!str) {
            flatmk_debug_puts("invalid ref\n");
            return -1;
        }
        for(int j = 0; j < v->iov_len; j++) {
            struct FastIpcPayload payload = { 0 };
            payload.data[0] = 0;
            fastipc_write(&payload);
            while(TaskEndpoint_invoke(CAP_POLL_INPUT) < 0) sched_yield();
            fastipc_read(&payload);
            if((int64_t) payload.data[0] < 0) {
                return count;
            }
            str[j] = payload.data[1];
            count++;
        }
    }
    return count;
}

static int64_t map_shared_fb(struct BasicTask this_task, struct RootPageTable target_rpt, uint64_t target_va, uint64_t target_len) {
    struct FastIpcPayload payload = {0};

    // Create local mapping.
    payload.data[0] = 0;
    payload.data[1] = target_va;
    payload.data[2] = target_len;

    // Put local page table.
    if(CapabilitySet_clone_cap(CAP_CAPSET, target_rpt.cap, CAP_BUFFER) < 0) flatmk_throw();
    if(BasicTask_put_ipc_cap(this_task, CAP_BUFFER, 1) < 0) flatmk_throw();
    
    fastipc_write(&payload);
    while(TaskEndpoint_invoke(CAP_FRAMEBUFFER) < 0) sched_yield();
    fastipc_read(&payload);

    if((int64_t) payload.data[0] < 0) {
        return (int64_t) payload.data[0];
    }
    return 0;
}

static int64_t vga_mmap(struct LinuxTask *lt, struct FileDescriptor *fd, uint64_t addr, uint64_t length, int linux_prot, int linux_flags, uint64_t offset) {
    int64_t ret;

    if(!(linux_prot & PROT_READ) || !(linux_prot & PROT_WRITE) || (linux_prot & PROT_EXEC) || !(linux_flags & MAP_FIXED) || offset != 0) {
        return -1;
    }

    ret = map_shared_fb(lt->host, lt->managed_rpt, addr, length);
    if(ret < 0) return ret;

    return addr;
}

int64_t do_openat(struct LinuxTask *lt, const char *path) {
    if(strcmp(path, "/dev/vga") == 0) {
        int fd = linux_task_allocate_fd(lt);
        if(fd < 0) return fd;
        lt->fds[fd].ops = &ops_vga;
        return fd;
    } else if(strcmp(path, "/dev/kbd") == 0) {
        int fd = linux_task_allocate_fd(lt);
        if(fd < 0) return fd;
        lt->fds[fd].ops = &ops_kbd;
        return fd;
    } else {
        return -1;
    }
}

struct FdOps ops_stdout = {
    .writev = console_writev
};

struct FdOps ops_stderr = {
    .writev = console_writev
};

struct FdOps ops_vga = {
    .mmap = vga_mmap
};

struct FdOps ops_kbd = {
    .readv = kbd_readv
};
