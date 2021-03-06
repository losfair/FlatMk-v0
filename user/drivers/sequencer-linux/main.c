// A FlatRt Sequencer that implements the Linux syscall interface.

#include <stddriver.h>
#include "syscalls.h"
#include "linux_task.h"
#include <stdatomic.h>
#include "elfloader.h"
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "mm.h"
#include "io.h"
#include "./linux/generated/init.h"

#define MON_STACK_SIZE 65536ull
#define PAGE_SIZE 4096ull

_Atomic uint64_t next_linux_task_id = 1;
_Atomic uint64_t next_cap_index_sequential = (0x1000 >> 8) << 6;
_Atomic uint64_t next_task_page_va = 0x20000000;
_Atomic uint64_t next_shadow_map_va = 0x600000000000;

const uint64_t elfload_temp_base = 0x1fff0000;

CPtr canonicalize_cap_index(uint64_t x) {
    return ((x >> 6) << 8) | (x & 0b111111);
}

CPtr acquire_cap() {
    return canonicalize_cap_index(atomic_fetch_add(&next_cap_index_sequential, 1));
}

void * acquire_uninitialized_pages(uint64_t n) {
    uint64_t va = atomic_fetch_add(&next_task_page_va, n * PAGE_SIZE);
    for(uint64_t i = 0; i < n; i++) {
        ASSERT_OK(RootPageTable_make_leaf(CAP_RPT, va + i * PAGE_SIZE));
        ASSERT_OK(RootPageTable_alloc_leaf(CAP_RPT, va + i * PAGE_SIZE, UserPteFlags_WRITABLE));
    }
    
    return (void *) va;
}

uint64_t acquire_shadow_map_va() {
    return atomic_fetch_add(&next_shadow_map_va, LT_SHADOW_MAP_SIZE);
}

void __attribute__((naked)) __host_entry_asm() {
    __asm__ volatile(
        "mov 8(%rdi), %rsp\n" // host_stack_end
        "call host_entry\n" // ensure stack alignment
        "ud2"
    );
}

void host_entry(struct LinuxTask *lt, int tag, enum TaskFaultReason reason, uint64_t _unused, uint64_t code) {
    struct TaskRegisters regs;
    char buf[512];

    if(lt->terminated) {
        flatmk_throw();
    }

    ASSERT_OK(BasicTask_get_all_registers(lt->managed, (uint64_t) &regs, sizeof(regs)));
    switch(reason) {
        case TaskFaultReason_VMAccess: {
            uint64_t fault_va = code;
            uint64_t fault_va_page = fault_va & (~(0xfffull));

            uint64_t prot = 0;

            // Lazy paging.
            if(linux_mm_validate_target_va(lt->mm, fault_va, &prot)) {
                ASSERT_OK(RootPageTable_put_page(lt->managed_rpt, lt->shadow_map_base + fault_va_page, fault_va_page, prot));
                ASSERT_OK(BasicTask_ipc_return(lt->host));
            } else {
                sprintf(buf, "linux: VM access fault at %p. RIP=%p\n", (void *) fault_va, (void *) regs.rip);
                flatmk_debug_puts(buf);
            }
            
            break;
        }
        case TaskFaultReason_IllegalInstruction:
            sprintf(buf, "linux: Illegal instruction\n");
            flatmk_debug_puts(buf);
            break;
        case TaskFaultReason_InvalidCapability:
            dispatch_syscall(lt, &regs);
            break;
        case TaskFaultReason_InvalidOperation:
            sprintf(buf, "linux: Invalid operation\n");
            flatmk_debug_puts(buf);
            break;
        default:
            break;
    }
    
    flatmk_throw();
}

void setup_initial_linux_stack(struct LinuxTask *lt, int argc, const char **argv, int envc, const char **envp) {
    // Initialize target stack.
    ASSERT_OK(libelfloader_build_and_apply_stack(lt->shadow_map_base + LT_STACK_START, LT_STACK_SIZE, CAP_RPT.cap, lt->managed.cap));

    // Shadow-mapped stack.
    uint8_t *stack_aux = (uint8_t *) (lt->shadow_map_base + LT_STACK_END);
    uint8_t *stack_aux_end = (uint8_t *) (lt->shadow_map_base + LT_STACK_END - 8192);
    uint64_t *stack_direct = (uint64_t *) stack_aux_end;
    uint64_t *stack_direct_end = (uint64_t *) (lt->shadow_map_base + LT_STACK_START);

    stack_aux -= 8;

    // Auxiliary vector.
    {
        Elf64_auxv_t *aux_vec = (Elf64_auxv_t *) stack_direct;

        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_NULL;
            x->a_un.a_val = 0;
        }

        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_PLATFORM;

            const char *platform = "x86_64";
            int len = strlen(platform + 1);
            stack_aux -= len;
            memcpy(stack_aux, platform, len);
            x->a_un.a_val = (uint64_t) stack_aux - lt->shadow_map_base;
        }

        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_SECURE;
            x->a_un.a_val = 0;
        }


        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_RANDOM;

            const uint8_t prand[16] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
            stack_aux -= sizeof(prand);
            memcpy(stack_aux, prand, sizeof(prand));
            x->a_un.a_val = (uint64_t) stack_aux - lt->shadow_map_base;
        }

        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_EGID;
            x->a_un.a_val = 0;
        }
        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_GID;
            x->a_un.a_val = 0;
        }
        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_EUID;
            x->a_un.a_val = 0;
        }
        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_UID;
            x->a_un.a_val = 0;
        }
        {
            Elf64_auxv_t *x = --aux_vec;
            x->a_type = AT_PAGESZ;
            x->a_un.a_val = 4096;
        }

        stack_direct = (uint64_t *) aux_vec;
    }

    // Initialize env vars.
    envp += envc;
    if(*envp != NULL) flatmk_throw();
    *(--stack_direct) = 0;
    for(int i = 0; i < envc; i++) {
        const char *s = *(--envp);
        int len = strlen(s) + 1; // '\0'
        stack_aux -= len;
        memcpy(stack_aux, s, len);
        *(--stack_direct) = (uint64_t) stack_aux - lt->shadow_map_base;
    }

    // Initialize args.
    argv += argc;
    if(*argv != NULL) flatmk_throw();
    *(--stack_direct) = 0;
    for(int i = 0; i < argc; i++) {
        const char *s = *(--argv);
        int len = strlen(s) + 1; // '\0'
        stack_aux -= len;
        memcpy(stack_aux, s, len);
        *(--stack_direct) = (uint64_t) stack_aux - lt->shadow_map_base;
    }

    // Push argc.
    *(--stack_direct) = argc;

    // Set RSP.
    ASSERT_OK(BasicTask_set_register(lt->managed, RSP_INDEX, (uint64_t) stack_direct - lt->shadow_map_base));
    // Insert region.
    ASSERT_OK(linux_mm_insert_region(lt->mm, LT_STACK_START, LT_STACK_END, UserPteFlags_WRITABLE));
}

void linux_task_start(const uint8_t *image, uint64_t image_len) {
    struct LinuxTask *lt = acquire_uninitialized_pages(1);
    memset(lt, 0, sizeof(struct LinuxTask));

    // Allocate resources for LT.
    lt->host_stack = acquire_uninitialized_pages(MON_STACK_SIZE / PAGE_SIZE);
    lt->host_stack_end = (void *) ((uint64_t) lt->host_stack + MON_STACK_SIZE);
    lt->host = BasicTask_new(acquire_cap());
    lt->managed = BasicTask_new(acquire_cap());
    lt->managed_capset = CapabilitySet_new(acquire_cap());
    lt->managed_rpt = RootPageTable_new(acquire_cap());
    lt->managed_fault_to_host = TaskEndpoint_new(acquire_cap());
    lt->managed_sched = TaskEndpoint_new(acquire_cap());
    lt->mm = NULL;
    lt->shadow_map_base = acquire_shadow_map_va();
    lt->terminated = 0;
    lt->current_brk = LT_HEAP_BASE;
    lt->current_mmap = LT_MMAP_BASE;
    lt->syscall_ret_buffer = TaskEndpoint_new(acquire_cap());

    // Set up stdio.
    lt->fds[1].ops = &ops_stdout;
    lt->fds[2].ops = &ops_stderr;

    // Initialized host & managed tasks.
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, lt->host.cap));
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, lt->managed.cap));

    // Set up an empty capset.
    ASSERT_OK(BasicTask_make_capset(CAP_ME, lt->managed_capset.cap));
    ASSERT_OK(BasicTask_put_capset(lt->managed, lt->managed_capset));

    // Set up the page table.
    ASSERT_OK(BasicTask_make_root_page_table(CAP_ME, lt->managed_rpt.cap));
    ASSERT_OK(BasicTask_put_root_page_table(lt->managed, lt->managed_rpt));

    // Set up MM.
    lt->mm = linux_mm_new(lt->managed.cap, lt->shadow_map_base, lt->shadow_map_base + LT_SHADOW_MAP_SIZE);

    // Set syscall delegation.
    ASSERT_OK(BasicTask_set_syscall_delegated(lt->managed, 1));

    // Load image.
    uint64_t entry_address;
    ASSERT_OK(libelfloader_load_and_apply(lt->mm, image, image_len, elfload_temp_base, CAP_RPT.cap, lt->managed.cap, &entry_address));

    const char *argv[] = {"test_task", NULL};
    const char *envp[] = {"PATH=/bin", NULL};
    setup_initial_linux_stack(lt, 1, argv, 1, envp);

    // Set up TLS for monitor thread.
    ASSERT_OK(BasicTask_set_register(lt->host, FS_BASE_INDEX, (uint64_t) FLATRT_DRIVER_GLOBAL_TLS));

    // Fetch monitor endpoint.
    ASSERT_OK(BasicTask_fetch_task_endpoint(
        lt->host,
        lt->managed_fault_to_host.cap, // call endpoint w/o flags
        (uint64_t) __host_entry_asm,
        (uint64_t) lt
    ));

    // Register fault handler.
    ASSERT_OK(BasicTask_put_fault_handler(lt->managed, lt->managed_fault_to_host))

    // Fetch scheduling endpoint.
    ASSERT_OK(BasicTask_fetch_task_endpoint(
        lt->managed,
        lt->managed_sched.cap | (((uint64_t )TaskEndpointFlags_TAGGABLE) << 48) | (1ull << 63),
        0, 0
    ));

    // Put to scheduler.
    sched_create(lt->managed_sched);
}

void linux_task_drop(struct LinuxTask *t) {
    flatmk_debug_puts("linux_task_drop: not implemented\n");
    flatmk_throw();
}

void main() {
    // Save the return endpoint before IPC calls.
    if(
        BasicTask_fetch_ipc_cap(CAP_ME, CAP_BUFFER_INITRET.cap, 0) < 0
    ) flatmk_throw();

    ASSERT_OK(RootPageTable_make_leaf(CAP_RPT, elfload_temp_base));
    
    // Pre-allocate cap leafs.
    for(int i = 0; i < 64; i++) {
        ASSERT_OK(CapabilitySet_make_leaf(CAP_CAPSET, 0x1000 + 0x100 * i));
    }

    linux_task_start(LINUX_INIT_ELF_BYTES, sizeof(LINUX_INIT_ELF_BYTES));

    // Return.
    TaskEndpoint_invoke(CAP_BUFFER_INITRET);
    flatmk_throw();
}
