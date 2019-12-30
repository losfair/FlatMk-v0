#![no_std]

#[macro_export]
macro_rules! ipc_entry_with_context {
    ($name:ident, $internal_name:ident, $context:ident, $tag:ident, $body:block) => {
        #[no_mangle]
        extern "C" fn $internal_name($context: u64, $tag: u64) -> ! {
            $body
        }

        #[naked]
        unsafe extern "C" fn $name() {
            asm!(
                concat!(r#"
                    mov %gs:0, %rsp
                    jmp "#, stringify!($internal_name), r#"
                "#) :::: "volatile"
            );
            loop {}
        }
    };
}

#[repr(C)]
pub struct FastIpcPayload {
    pub data: [u64; 8],
}

impl FastIpcPayload {
    pub fn read() -> FastIpcPayload {
        let result: FastIpcPayload;
        unsafe {
            asm!(
                r#"
                mov %xmm0, 0($0)
                mov %xmm1, 8($0)
                mov %xmm2, 16($0)
                mov %xmm3, 24($0)
                mov %xmm4, 32($0)
                mov %xmm5, 40($0)
                mov %xmm6, 48($0)
                mov %xmm7, 56($0)
            "# : : "r"(&mut result) : : "volatile");
        }
        result
    }

    pub fn write(&self) {
        unsafe {
            asm!(
                r#"
                mov 0($0), %xmm0
                mov 8($0), %xmm1
                mov 16($0), %xmm2
                mov 24($0), %xmm3
                mov 32($0), %xmm4
                mov 40($0), %xmm5
                mov 48($0), %xmm6
                mov 56($0), %xmm7
            "# : : "r"(self) : : "volatile");
        }
    }
}
