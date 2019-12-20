/// Enables SSE/AVX instructions.
unsafe fn enable_sse() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x600, %rax // CR4.OSFXSR + CR4.OSXMMEXCPT
        mov %rax, %cr4
    "# ::: "rax" : "volatile");
}

/// Enables fsgsbase instructions.
unsafe fn _enable_fsgsbase() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x8000, %rax // CR4.FSGSBASE
        mov %rax, %cr4
    "# ::: "rax" : "volatile");
}

/// Early architecture-specific initialization.
pub unsafe fn arch_early_init() {
    enable_sse();
    //enable_fsgsbase();

    super::exception::init_gdt();
    super::exception::init_idt();
    super::exception::init_interrupts();
}

/// Late architecture-specific initialization.
pub unsafe fn arch_late_init() {}
