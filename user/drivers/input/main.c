#include <stddriver.h>

struct Interrupt CAP_INTERRUPT_33 = { 0x10 };
struct BasicTask CAP_KBD_IH = { 0x11 };

uint8_t __kbd_ih_stack[65536];

void __attribute__((naked)) __kbd_ih_entry_asm() {
    __asm__ volatile(
        "mov %rdi, %rsp\n"
        "call kbd_ih_entry\n"
        "ud2\n"
    );
}

void main() {
    char buf[256];

    flatmk_debug_puts("input: Setting up keyboard.\n");

    ASSERT_OK(BasicTask_fetch_shallow_clone(CAP_ME, CAP_KBD_IH.cap));
    ASSERT_OK(Interrupt_bind(CAP_INTERRUPT_33, CAP_KBD_IH, (uint64_t) __kbd_ih_entry_asm, (uint64_t) __kbd_ih_stack + sizeof(__kbd_ih_stack)));

    flatmk_debug_puts("input: Keyboard initialized.\n");
    BasicTask_ipc_return(CAP_ME);
}

void kbd_ih_entry() {
    flatmk_debug_puts("Keyboard interrupt.\n");
    BasicTask_ipc_return(CAP_KBD_IH);
}
