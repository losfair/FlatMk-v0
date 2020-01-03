#include "io.h"
#include <stdio.h>

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

struct FdOps ops_stderr = {
    .writev = console_writev
};
