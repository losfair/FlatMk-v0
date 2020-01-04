#include <stddriver.h>
#include "syscalls.h"
#include "linux_task.h"
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "io.h"
#include <time.h>

#define PAGE_SIZE 4096ull

#define ARCH_SET_GS		0x1001
#define ARCH_SET_FS		0x1002
#define ARCH_GET_FS		0x1003
#define ARCH_GET_GS		0x1004

void * acquire_umem(struct LinuxTask *lt, uint64_t uaddr, uint64_t size, int write) {
    uint64_t upage = uaddr & (~(0xfffull));
    uint64_t uend = uaddr + size;

    // Overflow/ZST
    if(uend <= uaddr) {
        return NULL;
    }

    for(uint64_t i = upage; i < uend; i += PAGE_SIZE) {
        uint64_t prot;
        if(linux_mm_validate_target_va(lt->mm, i, &prot) != 1) {
            return NULL;
        }
        if(write && !(prot & UserPteFlags_WRITABLE)) {
            return NULL;
        }
    }

    return (void *) (lt->shadow_map_base + uaddr);
}

static uint64_t round_up_to_page_size(uint64_t x) {
    if(x % PAGE_SIZE != 0) {
        x = (x & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
    }
    return x;
}

static int64_t do_anonymous_map(struct LinuxTask *lt, uint64_t addr, uint64_t length, int linux_prot, int linux_flags, uint64_t offset) {
    // Must be readable.
    if(!(linux_prot & PROT_READ)) {
        return -1;
    }

    // We don't yet support fixed mapping.
    if(linux_flags & MAP_FIXED) {
        return -1;
    }

    // Set up flags.
    uint64_t flatmk_flags = 0;
    if(linux_prot & PROT_WRITE) flatmk_flags |= UserPteFlags_WRITABLE;
    if(linux_prot & PROT_EXEC) flatmk_flags |= UserPteFlags_EXECUTABLE;

    uint64_t end = round_up_to_page_size(lt->current_mmap + length);
    if(end < lt->current_mmap || end > LT_SHADOW_MAP_SIZE) return -1; // overflow
    if(end == lt->current_mmap) return 0; // no need to allocate

    for(uint64_t i = lt->current_mmap; i < end; i += PAGE_SIZE) {
        ASSERT_OK(RootPageTable_alloc_leaf(CAP_RPT, lt->shadow_map_base + i, flatmk_flags));
    }
    ASSERT_OK(linux_mm_insert_region(lt->mm, LT_MMAP_BASE, end, flatmk_flags));
    void *ret = (void *) lt->current_mmap;
    lt->current_mmap = end;

    char buf[128];
    sprintf(buf, "mmap update: %p\n", (void *) lt->current_mmap);
    flatmk_debug_puts(buf);
    return (int64_t) ret;
}

void dispatch_syscall(struct LinuxTask *lt, struct TaskRegisters *registers) {
    char buf[256];

    //sprintf(buf, "SYSCALL: %d\n", (int) registers->rax);
    //flatmk_debug_puts(buf);

    ASSERT_OK(BasicTask_fetch_ipc_cap(lt->host, lt->syscall_ret_buffer.cap, 0));

    switch(registers->rax) {
        case __NR_getuid:
        case __NR_geteuid:
        case __NR_getgid:
        case __NR_getegid:
            registers->rax = 0;
            break;
        case __NR_arch_prctl:
            if(registers->rdi == ARCH_SET_FS) {
                registers->fs_base = registers->rsi;
                registers->rax = 0;
            } else {
                registers->rax = -1;
            }
            break;
        case __NR_brk:
            if(registers->rdi == 0) {
                registers->rax = lt->current_brk;
            } else if(registers->rdi > LT_SHADOW_MAP_SIZE) {
                registers->rax = -1;
            } else {
                uint64_t current_top = round_up_to_page_size(lt->current_brk);
                uint64_t requested_top = round_up_to_page_size(registers->rdi);
                if(requested_top > current_top) {
                    for(uint64_t i = current_top; i < requested_top; i += PAGE_SIZE) {
                        ASSERT_OK(RootPageTable_alloc_leaf(CAP_RPT, lt->shadow_map_base + i, UserPteFlags_WRITABLE));
                    }
                    ASSERT_OK(linux_mm_insert_region(lt->mm, LT_HEAP_BASE, requested_top, UserPteFlags_WRITABLE));
                    lt->current_brk = registers->rdi;
                }
                registers->rax = registers->rdi;
            }
            sprintf(buf, "brk(%p) = %p\n", (void *) registers->rdi, (void *) registers->rax);
            flatmk_debug_puts(buf);
            break;
        case __NR_uname: {
            struct utsname *un = acquire_umem(lt, registers->rdi, sizeof(struct utsname), 1);
            if(!un) {
                registers->rax = -1;
                break;
            }
            strncpy(un->sysname, "Linux", sizeof(un->sysname));
            strncpy(un->nodename, "Linux", sizeof(un->nodename));
            strncpy(un->release, "5.3.0", sizeof(un->release));
            strncpy(un->version, "5.3.0", sizeof(un->version));
            strncpy(un->machine, "Test", sizeof(un->machine));
            registers->rax = 0;
            break;
        }
        case __NR_openat: {
            int dirfd = registers->rdi;
            uint64_t pathname = registers->rsi;
            int flags = registers->rdx;
            int mode = registers->r10;

            char namebuf[128];

            for(int i = 0; i < sizeof(namebuf); i++) {
                const char *c = acquire_umem(lt, pathname + i, 1, 0);
                if(!c) {
                    registers->rax = -1;
                    goto out;
                }
                namebuf[i] = *c;
                if(!namebuf[i]) break;
            }
            namebuf[sizeof(namebuf) - 1] = '\0';
            if(dirfd == 0xffffff9c) {
                // current directory
                registers->rax = do_openat(lt, namebuf);
            } else {
                registers->rax = -1;
            }
            break;
        }
        case __NR_readv:
        case __NR_writev: {
            int fd = registers->rdi;
            uint64_t iovs_u = registers->rsi;
            uint64_t iovcnt = registers->rdx;

            if(
                fd < 0 || fd >= LT_FD_TABLE_SIZE || lt->fds[fd].ops == NULL ||
                iovcnt > 255
            ) {
                registers->rax = -1;
                break;
            }

            struct iovec *iovs = acquire_umem(lt, iovs_u, sizeof(struct iovec) * iovcnt, 0);
            if(!iovs) {
                registers->rax = -1;
                break;
            }

            if(registers->rax == __NR_readv) {
                if(!lt->fds[fd].ops->readv) registers->rax = -1;
                else registers->rax = lt->fds[fd].ops->readv(lt, &lt->fds[fd], iovs, iovcnt);
            } else {
                if(!lt->fds[fd].ops->writev) registers->rax = -1;
                else registers->rax = lt->fds[fd].ops->writev(lt, &lt->fds[fd], iovs, iovcnt);
            }
            break;
        }
        case __NR_read:
        case __NR_write: {
            int fd = registers->rdi;
            if(
                fd < 0 || fd >= LT_FD_TABLE_SIZE || lt->fds[fd].ops == NULL
            ) {
                registers->rax = -1;
                break;
            }

            struct iovec iov = {
                .iov_base = (void *) registers->rsi,
                .iov_len = registers->rdx
            };
            if(registers->rax == __NR_read) {
                if(!lt->fds[fd].ops->readv) registers->rax = -1;
                else registers->rax = lt->fds[fd].ops->readv(lt, &lt->fds[fd], &iov, 1);
            } else {
                if(!lt->fds[fd].ops->writev) registers->rax = -1;
                else registers->rax = lt->fds[fd].ops->writev(lt, &lt->fds[fd], &iov, 1);
            }
            break;
        }
        case __NR_fstat: {
            int fd = registers->rdi;
            struct stat *statbuf = acquire_umem(lt, registers->rsi, sizeof(struct stat), 1);
            if(!statbuf) {
                registers->rax = -EFAULT;
                break;
            }
            memset(statbuf, 0, sizeof(statbuf));
            registers->rax = 0;
            break;
        }
        case __NR_nanosleep: {
            const struct timespec *req = acquire_umem(lt, registers->rdi, sizeof(struct timespec), 0);
            struct timespec *rem = acquire_umem(lt, registers->rsi, sizeof(struct timespec), 1);
            if(!req) {
                registers->rax = -EFAULT;
                break;
            }
            uint64_t ns = (uint64_t) req->tv_sec * 1000000000ull + req->tv_nsec;
            sched_nanosleep(ns);
            if(rem) memset(rem, 0, sizeof(struct timespec));
            registers->rax = 0;
            break;
        }
        case __NR_exit_group:
            sprintf(buf, "Program exited with code %d.\n", (int) registers->rdi);
            flatmk_debug_puts(buf);
            while(1) sched_yield();
            break;
        case __NR_mmap: {
            uint64_t addr = registers->rdi;
            uint64_t len = registers->rsi;
            int prot = registers->rdx;
            int flags = registers->r10;
            int fd = registers->r8;
            uint64_t off = registers->r9;

            // Anonymous map.
            if(flags & MAP_ANONYMOUS) {
                registers->rax = do_anonymous_map(lt, addr, len, prot, flags, off);
                break;
            }

            if(fd < 0 || fd >= LT_FD_TABLE_SIZE || lt->fds[fd].ops == NULL || lt->fds[fd].ops->mmap == NULL) {
                registers->rax = -1;
                break;
            }
            registers->rax = lt->fds[fd].ops->mmap(lt, &lt->fds[fd], addr, len, prot, flags, off);
            break;
        }
        case __NR_munmap:
            // Just leak memory.
            registers->rax = 0;
            break;
        default: {
            sprintf(buf, "dispatch_syscall: Unknown linux syscall index: %lu\n", registers->rax);
            flatmk_debug_puts(buf);

            registers->rax = (uint64_t) -1ll;
            
            break;
        }
    }

    out:

    ASSERT_OK(BasicTask_set_all_registers(lt->managed, (uint64_t) registers, sizeof(struct TaskRegisters)));
    TaskEndpoint_invoke(lt->syscall_ret_buffer);
}
