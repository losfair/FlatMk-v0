use crate::softuser::SoftuserContext;

pub unsafe fn arch_softuser_enter(ctx: &mut SoftuserContext) -> ! {
    llvm_asm!(
        r#"
            mov %gs:8, %rsp
            push %rax
            swapgs
            sti
            jmp softuser_context_lowlevel_entry
        "# :: "{rdi}"(ctx) :: "volatile"
    );
    loop {}
}

pub unsafe fn arch_softuser_hostcall_enter() {
    llvm_asm!(
        r#"
            cli
            swapgs
        "# :::: "volatile"
    );
}

pub unsafe fn arch_softuser_hostcall_leave() {
    llvm_asm!(
        r#"
            swapgs
            sti
        "# :::: "volatile"
    );
}

pub unsafe fn arch_softuser_wait_for_interrupt_in_user_context() {
    llvm_asm!(
        r#"
            hlt
        "# :::: "volatile"
    );
}