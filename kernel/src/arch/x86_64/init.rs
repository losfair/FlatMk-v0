/// Enables SSE/AVX instructions.
unsafe fn enable_sse() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x600, %rax // CR4.OSFXSR + CR4.OSXMMEXCPT
        mov %rax, %cr4
    "# ::: "rax" : "volatile");
}

/// Enables global flag in PT entries.
unsafe fn enable_global_flag() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x80, %rax // CR4.PGE
        mov %rax, %cr4
    "# ::: "rax" : "volatile");
}

/// Enables PCID.
#[cfg(feature = "x86_pcid")]
unsafe fn enable_pcid() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x20000, %rax // CR4.PCIDE
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
    enable_global_flag();

    #[cfg(feature = "x86_pcid")]
    {
        enable_pcid();
    }

    //enable_fsgsbase();

    super::exception::init_gdt();
    super::exception::init_idt();
}

/// Late architecture-specific initialization.
pub unsafe fn arch_late_init() {
    super::apic::init_apic();
}
