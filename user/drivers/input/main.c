#include <stddriver.h>

struct Interrupt CAP_INTERRUPT_33 = { 0x10 };
struct BasicTask CAP_KBD_IH = { 0x11 };
struct TaskEndpoint CAP_POLL_INPUT = { 0x12 };
struct X86IoPort CAP_PORT_0x60 = { 0x13 };
struct X86IoPort CAP_PORT_0x61 = { 0x14 };

struct BasicTask dyn_cap_poll_input_listener;

struct ReentrancyGuard ih_or_poll = { 0 };
struct TaskEndpoint dyn_cap_input_callback;
int has_input_callback = 0;

uint8_t __kbd_ih_stack[65536];
uint8_t __kbd_poll_entry_stack[65536];

void __attribute__((naked)) __kbd_ih_entry_asm() {
    __asm__ volatile(
        "mov %rdi, %rsp\n"
        "call kbd_ih_entry\n"
        "ud2\n"
    );
}

void __attribute__((naked)) __kbd_poll_entry_asm() {
    __asm__ volatile(
        "mov %rdi, %rsp\n"
        "call kbd_poll_entry\n"
        "ud2\n"
    );
}

void main() {
    char buf[256];

    flatmk_debug_puts("input: Setting up keyboard.\n");

    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, CAP_KBD_IH.cap));
    ASSERT_OK(Interrupt_bind(CAP_INTERRUPT_33, CAP_KBD_IH, (uint64_t) __kbd_ih_entry_asm, (uint64_t) __kbd_ih_stack + sizeof(__kbd_ih_stack)));

    flatmk_debug_puts("input: Keyboard initialized.\n");

    dyn_cap_poll_input_listener.cap = libcapalloc_allocate();
    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, dyn_cap_poll_input_listener.cap));
    ASSERT_OK(BasicTask_fetch_task_endpoint(
        dyn_cap_poll_input_listener,
        CAP_POLL_INPUT.cap,
        (uint64_t) __kbd_poll_entry_asm,
        (uint64_t) __kbd_poll_entry_stack + sizeof(__kbd_poll_entry_stack)
    ));

    dyn_cap_input_callback.cap = libcapalloc_allocate();

    flatmk_debug_puts("input: Initialization completed.\n");
    BasicTask_ipc_return(CAP_ME);
}

static inline void kbd_reset() {
    uint8_t a = X86IoPort_inb(CAP_PORT_0x61);
    a |= 0x82;
    ASSERT_OK(X86IoPort_outb(CAP_PORT_0x61, a));
    a &= 0x7f;
    ASSERT_OK(X86IoPort_outb(CAP_PORT_0x61, a));
}

static inline uint8_t kbd_read_scancode() {
    return X86IoPort_inb(CAP_PORT_0x60);
}

void kbd_ih_entry() {
    //flatmk_debug_puts("Keyboard interrupt.\n");
    uint8_t scancode = kbd_read_scancode();
    kbd_reset();

    if(!reentrancy_guard_try_lock(&ih_or_poll)) {
        BasicTask_ipc_return(CAP_KBD_IH);
        flatmk_throw();
    }

    if(has_input_callback) {
        struct TaskEndpoint buffer = { libcapalloc_allocate() };
        ASSERT_OK(BasicTask_fetch_ipc_cap(CAP_KBD_IH, buffer.cap, 0));
        ASSERT_OK(sched_create(buffer));
        libcapalloc_release(buffer.cap);
        
        ASSERT_OK(BasicTask_put_ipc_cap(CAP_KBD_IH, dyn_cap_input_callback.cap, 0));
        has_input_callback = 0;

        struct FastIpcPayload payload = {0};
        payload.data[0] = 0;
        payload.data[1] = scancode;
        fastipc_write(&payload);
    }
    reentrancy_guard_unlock(&ih_or_poll);
    BasicTask_ipc_return(CAP_KBD_IH);
    flatmk_throw();
}

void kbd_poll_entry() {
    if(!reentrancy_guard_try_lock(&ih_or_poll)) {
        flatmk_debug_puts("kbd_poll_entry: Cannot take reentrancy guard.\n");
        flatmk_throw();
    }

    ASSERT_OK(BasicTask_fetch_ipc_cap(dyn_cap_poll_input_listener, dyn_cap_input_callback.cap, 0));
    has_input_callback = 1;

    reentrancy_guard_unlock(&ih_or_poll);

    ASSERT_OK(TrivialSyscallEntry_sched_drop(CAP_TRIVIAL_SYSCALL));
    flatmk_throw();
}