.globl __copy_user_checked_argreversed
__copy_user_checked_argreversed:
    cld
    mov %rdx, %rcx

.globl __copy_user_checked_argreversed__copyinst
__copy_user_checked_argreversed__copyinst:
    rep movsb

.globl __copy_user_checked_argreversed__copyend
__copy_user_checked_argreversed__copyend:
    mov %rcx, %rax
    ret

.globl arch_lowlevel_syscall_entry
arch_lowlevel_syscall_entry:
    swapgs
    mov %rsp, %gs:16
    mov %gs:8, %rsp

    # Reserve space for the unused softuser area.
    sub $8 * 6, %rsp # softuser_args
    pushq $0 # has_softuser_args = false

    # `fs` and `gs` are lazily read on task switch.
    pushq $0 # fs
    pushq $0 # gs
    push %r11 # rflags
    push %rcx # rip
    push %rbp # rbp
    push %gs:16 # rsp
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rbx
    push %rax
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    mov %rsp, %rdi
    jmp syscall_entry
