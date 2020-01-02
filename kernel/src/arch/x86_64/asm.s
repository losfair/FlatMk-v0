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
