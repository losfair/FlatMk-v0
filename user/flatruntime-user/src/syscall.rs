use alloc::boxed::Box;
use core::intrinsics::abort;

#[naked]
#[inline(never)]
unsafe extern "C" fn _do_syscall() {
    asm!(
        r#"
        movq %rcx, %r10
        movq 8(%rsp), %rax
        syscall
        retq
    "#
    );
}

static mut CAP_SLOTS: [bool; 128] = [false; 128];

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum RootTaskCapRequest {
    AnyX86IoPort = 0,
    LocalMap = 1,
    LocalMmio = 2,
}

#[derive(Copy, Clone, Debug)]
#[repr(u32)]
enum SyscallIndex {
    Call = 0,
}

#[repr(align(4096))]
pub struct Delegation([u8; 4096]);

impl Delegation {
    pub const fn new() -> Delegation {
        Delegation([0; 4096])
    }
}

pub struct CPtr(u64);

impl CPtr {
    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        let syscall: unsafe extern "C" fn(i64, i64, i64, i64, i64, i64, i64) -> i64 =
            core::mem::transmute(_do_syscall as usize);
        syscall(
            self.0 as _,
            p0,
            p1,
            p2,
            p3,
            0,
            SyscallIndex::Call as u32 as _,
        )
    }

    pub fn index(&self) -> u64 {
        self.0
    }
}

pub struct RootCap(CPtr);

pub struct RootResources {
    pub x86_port: AnyX86Port,
    pub local_mapper: crate::mm::LocalMapper,
    pub local_mmio: crate::mm::LocalMmio,
}

impl RootCap {
    pub unsafe fn init() -> RootCap {
        CAP_SLOTS[0] = true; // any x86 port
        RootCap(CPtr(0))
    }

    /// Must be panic-free to avoid recursive panicks.
    pub unsafe fn into_resources(self) -> RootResources {
        RootResources {
            x86_port: self.make_any_x86_port().unwrap_or_else(|| abort()),
            local_mapper: self.make_local_mapper().unwrap_or_else(|| abort()),
            local_mmio: self.make_local_mmio().unwrap_or_else(|| abort()),
        }
    }

    pub unsafe fn make_any_x86_port(&self) -> Option<AnyX86Port> {
        if let Some(cptr) = alloc_cap() {
            let mut del = Box::new(Delegation::new());
            if self.0.call(
                cptr.0 as _,
                RootTaskCapRequest::AnyX86IoPort as u32 as _,
                &mut *del as *mut _ as i64,
                0,
            ) == 0
            {
                Box::leak(del);
                Some(AnyX86Port { cap: cptr })
            } else {
                Box::leak(del);
                None
            }
        } else {
            None
        }
    }

    pub unsafe fn make_local_mapper(&self) -> Option<crate::mm::LocalMapper> {
        if let Some(cptr) = alloc_cap() {
            if self.0.call(
                cptr.0 as _,
                RootTaskCapRequest::LocalMap as u32 as _,
                0,
                0,
            ) == 0
            {
                Some(crate::mm::LocalMapper::new(cptr))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub unsafe fn make_local_mmio(&self) -> Option<crate::mm::LocalMmio> {
        if let Some(cptr) = alloc_cap() {
            let mut del = Box::new(Delegation::new());
            if self.0.call(
                cptr.0 as _,
                RootTaskCapRequest::LocalMmio as u32 as _,
                &mut *del as *mut _ as i64,
                0,
            ) == 0
            {
                Box::leak(del);
                Some(crate::mm::LocalMmio::new(cptr))
            } else {
                Box::leak(del);
                None
            }
        } else {
            None
        }
    }
}

pub struct AnyX86Port {
    cap: CPtr,
}

impl AnyX86Port {
    pub unsafe fn get_port(&self, id: u16) -> Option<CPtr> {
        if let Some(cptr) = alloc_cap() {
            if self.cap.call(cptr.0 as _, id as _, 0, 0) == 0 {
                Some(cptr)
            } else {
                None
            }
        } else {
            None
        }
    }
}

unsafe fn alloc_cap() -> Option<CPtr> {
    for i in 0..CAP_SLOTS.len() {
        if !CAP_SLOTS[i] {
            CAP_SLOTS[i] = true;
            return Some(CPtr(i as u64));
        }
    }
    None
}
