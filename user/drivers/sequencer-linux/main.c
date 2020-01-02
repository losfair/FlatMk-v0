// A FlatRt Sequencer that implements the Linux syscall interface.

#include <stddriver.h>
#include "syscalls.h"
#include "linux_task.h"
#include <stdatomic.h>
#include "elfloader.h"
#include <stdio.h>
#include "./linux/generated/init.h"

struct TaskEndpoint CAP_BUFFER_INITRET = { 0x12 };

#define MON_STACK_SIZE 65536ull
#define PAGE_SIZE 4096ull
#define SHADOW_MAP_SIZE 0x100000000

_Atomic uint64_t next_linux_task_id = 1;
_Atomic uint64_t next_cap_index_sequential = (0x1000 >> 8) << 5;
_Atomic uint64_t next_task_page_va = 0x20000000;
_Atomic uint64_t next_shadow_map_va = 0xa00000000000;

const uint64_t elfload_temp_base = 0x1fff0000;
const uint64_t target_stack_end = 0x80000000;
const uint64_t target_stack_size = 1048576;
const uint64_t target_stack_start = target_stack_end - target_stack_size;

CPtr canonicalize_cap_index(uint64_t x) {
    return ((x >> 5) << 8) | (x & 0b11111);
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
    return atomic_fetch_add(&next_shadow_map_va, SHADOW_MAP_SIZE);
}

void __attribute__((naked)) __host_entry_asm() {
    __asm__ volatile(
        "mov 8(%rdi), %rsp\n" // host_stack_end
        "call host_entry\n" // ensure stack alignment
        "ud2"
    );
}

void host_entry(struct LinuxTask *lt, int tag, enum TaskFaultReason reason) {
    struct TaskRegisters regs;
    char buf[512];

    if(lt->terminated) {
        flatmk_throw();
    }

    ASSERT_OK(BasicTask_get_all_registers(lt->managed, (uint64_t) &regs, sizeof(regs)));
    switch(reason) {
        case TaskFaultReason_VMAccess:
            sprintf(buf, "linux: VM Access failure\n");
            flatmk_debug_puts(buf);
            break;
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

void linux_task_start(const uint8_t *image, uint64_t image_len) {
    struct LinuxTask *lt = acquire_uninitialized_pages(1);

    // Allocate resources for LT.
    lt->host_stack = acquire_uninitialized_pages(MON_STACK_SIZE / PAGE_SIZE);
    lt->host_stack_end = (void *) ((uint64_t) lt->host_stack + MON_STACK_SIZE);
    lt->host = BasicTask_new(acquire_cap());
    lt->managed = BasicTask_new(acquire_cap());
    lt->managed_capset = CapabilitySet_new(acquire_cap());
    lt->managed_rpt = RootPageTable_new(acquire_cap());
    lt->managed_fault_to_host = TaskEndpoint_new(acquire_cap());
    lt->managed_sched = TaskEndpoint_new(acquire_cap());
    lt->shadow_map_base = acquire_shadow_map_va();
    lt->terminated = 0;

    // Initialized host & managed tasks.
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, lt->host.cap));
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, lt->managed.cap));

    // Set up an empty capset.
    ASSERT_OK(BasicTask_make_capset(CAP_ME, lt->managed_capset.cap));
    ASSERT_OK(BasicTask_put_capset(lt->managed, lt->managed_capset));

    // Set up the page table.
    ASSERT_OK(BasicTask_make_root_page_table(CAP_ME, lt->managed_rpt.cap));
    ASSERT_OK(BasicTask_put_root_page_table(lt->managed, lt->managed_rpt));

    // Load image.
    uint64_t entry_address;
    ASSERT_OK(libelfloader_load_and_apply(image, image_len, elfload_temp_base, lt->managed_rpt.cap, lt->managed.cap, &entry_address));

    // Initialize target stack.
    ASSERT_OK(libelfloader_build_and_apply_stack(target_stack_start, target_stack_size, lt->managed_rpt.cap, lt->managed.cap));

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
