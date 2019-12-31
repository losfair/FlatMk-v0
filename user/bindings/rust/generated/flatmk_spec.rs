// This file is generated by flatmk-codegen. Do not edit.

/// A request to a BasicTask/BasicTaskWeak endpoint.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum BasicTaskRequest {
	Ping = 0,
	FetchShallowClone = 1,
	FetchCapSet = 2,
	FetchRootPageTable = 3,
	FetchWeak = 4,
	FetchTaskEndpoint = 5,
	FetchIpcCap = 6,
	PutIpcCap = 7,
	PutCapSet = 8,
	PutRootPageTable = 9,
	MakeCapSet = 10,
	MakeRootPageTable = 11,
	SetRegister = 12,
	HasWeak = 13,
	IpcReturn = 14,
}

/// A request to a capability set.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum CapSetRequest {
	MakeLeafSet = 0,
	CloneCap = 1,
	DropCap = 2,
	FetchCap = 3,
	PutCap = 4,
	MoveCap = 6,
	GetCapType = 7,
	FetchCapMove = 8,
	PutCapMove = 9,
}

/// The type of a capability endpoint.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum CapType {
	Other = 0,
	TaskEndpoint = 1,
	RootPageTable = 2,
}

/// A request to an interrupt endpoint.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum InterruptRequest {
	Bind = 0,
	Unbind = 1,
}

/// A request to an IPC endpoint for another task.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum IpcRequest {
	SwitchTo = 0,
	IsCapTransfer = 1,
	IsTaggable = 2,
	IsReply = 3,
	SetTag = 4,
	GetTag = 5,
	Ping = 6,
}

/// Kernel error codes.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum KernelError {
	OutOfMemory = -8,
	InvalidReference = -7,
	EmptyCapability = -6,
	EmptyObject = -5,
	InvalidAddress = -4,
	InvalidState = -3,
	NotImplemented = -2,
	InvalidArgument = -1,
}

/// A request to a root page table.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum RootPageTableRequest {
	MakeLeaf = 0,
	AllocLeaf = 1,
	PutPage = 2,
	FetchPage = 3,
	DropPage = 4,
	SetProtection = 5,
}

/// A request to the root capability.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum RootTaskCapRequest {
	X86IoPort = 0,
	Mmio = 1,
	MakeIdle = 2,
	Interrupt = 3,
	DebugPutchar = 4,
}

/// A request to an X86 I/O port.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum X86IoPortRequest {
	Read = 0,
	Write = 1,
}

	/// Flags for a task endpoint.
bitflags! {
	pub struct TaskEndpointFlags: u64 {
		const CAP_TRANSFER = 1 << 0;
		const TAGGABLE = 1 << 1;
	}
}

	/// Flags for a user page table entry.
bitflags! {
	pub struct UserPteFlags: u64 {
		const WRITABLE = 1 << 0;
		const EXECUTABLE = 1 << 1;
	}
}

/// A strong or weak reference to a task.
#[derive(Copy, Clone, Debug)]
pub struct BasicTask {
    cap: CPtr
}

impl Into<CPtr> for BasicTask {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl BasicTask {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Invokes an invalid operation on this capability. Useful for benchmarking.
	pub unsafe fn call_invalid(
		&self,
	) -> i64 {
		self.cap.call(-1i64, 0i64, 0i64, 0i64, )
	}

	/// Fetch the capability set of this task into the current task's capability set.
	pub unsafe fn fetch_capset(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchCapSet as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Fetches a capability from the IPC capability buffer of this task. The capability is moved instead of cloned.
	pub unsafe fn fetch_ipc_cap(
		&self,
		out: &CPtr,
		index: u64,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchIpcCap as i64, out.index() as i64, index as i64, 0i64, )
	}

	/// Fetch the root page table of this task into the current task's capability set.
	pub unsafe fn fetch_root_page_table(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchRootPageTable as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Makes a shallow clone for this task. The clone will always be a strong reference.
	/// 
	/// The resulting task shares the same capability set and page table with this task, but has its own state flags and execution context.
	pub unsafe fn fetch_shallow_clone(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchShallowClone as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Fetches an IPC endpoint to this task.
	/// 
	/// The first argument `mixed_arg1` is a mixed argument that contains several properties:
	/// 
	/// - Bits 0 to 47 (inclusively) is a capability pointer in the current task's capability set to write to.
	/// - Bits 48 to 62 is a bitflag set of type `TaskEndpointFlags`.
	/// - Bit 63 indicates whether the new endpoint is a reply endpoint.
	pub unsafe fn fetch_task_endpoint(
		&self,
		mixed_arg1: u64,
		pc: u64,
		user_context: u64,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchTaskEndpoint as i64, mixed_arg1 as i64, pc as i64, user_context as i64, )
	}

	/// Makes a weak reference for this task.
	pub unsafe fn fetch_weak(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::FetchWeak as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Returns whether there exists weak references to this task.
	pub unsafe fn has_weak(
		&self,
	) -> i64 {
		self.cap.call(BasicTaskRequest::HasWeak as i64, 0i64, 0i64, 0i64, )
	}

	/// Fast path for returning from an IPC call, by automatically invoking the 0th entry in this task's IPC capability buffer.
	pub unsafe fn ipc_return(
		&self,
	) -> i64 {
		self.cap.call(BasicTaskRequest::IpcReturn as i64, 0i64, 0i64, 0i64, )
	}

	/// Makes a capability set and puts its endpoint in the current task's capability set. (FIXME: Maybe this shouldn't be in BasicTask?)
	pub unsafe fn make_capset(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::MakeCapSet as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Makes a root page table and puts its endpoint in the current task's capability set. (FIXME: Maybe this shouldn't be in BasicTask?)
	pub unsafe fn make_root_page_table(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(BasicTaskRequest::MakeRootPageTable as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Detects whether the reference is still alive if it is a weak reference. Always return 0 for strong references.
	pub unsafe fn ping(
		&self,
	) -> i64 {
		self.cap.call(BasicTaskRequest::Ping as i64, 0i64, 0i64, 0i64, )
	}

	/// Puts an endpoint to a capability set in the current task's capability set into this task's capability set.
	pub unsafe fn put_capset(
		&self,
		cptr: &CapabilitySet,
	) -> i64 {
		self.cap.call(BasicTaskRequest::PutCapSet as i64, cptr.cptr().index() as i64, 0i64, 0i64, )
	}

	/// Puts a capability into the IPC capability buffer of this task. The capability is moved instead of cloned.
	pub unsafe fn put_ipc_cap(
		&self,
		cptr: &CPtr,
		index: u64,
	) -> i64 {
		self.cap.call(BasicTaskRequest::PutIpcCap as i64, cptr.index() as i64, index as i64, 0i64, )
	}

	/// Puts an endpoint to a root page table in the current task's capability set into this task's capability set.
	pub unsafe fn put_root_page_table(
		&self,
		cptr: &RootPageTable,
	) -> i64 {
		self.cap.call(BasicTaskRequest::PutRootPageTable as i64, cptr.cptr().index() as i64, 0i64, 0i64, )
	}

	/// Sets a saved register of this task. Calling this method on a running task has undefined result.
	pub unsafe fn set_register(
		&self,
		index: u64,
		value: u64,
	) -> i64 {
		self.cap.call(BasicTaskRequest::SetRegister as i64, index as i64, value as i64, 0i64, )
	}

}

/// A capability set.
#[derive(Copy, Clone, Debug)]
pub struct CapabilitySet {
    cap: CPtr
}

impl Into<CPtr> for CapabilitySet {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl CapabilitySet {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Clones a capability.
	pub unsafe fn clone_cap(
		&self,
		src: &CPtr,
		dst: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::CloneCap as i64, src.index() as i64, dst.index() as i64, 0i64, )
	}

	/// Drops a capability.
	pub unsafe fn drop_cap(
		&self,
		cptr: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::DropCap as i64, cptr.index() as i64, 0i64, 0i64, )
	}

	/// Fetches a capability from this capability set to the current task's capability set.
	pub unsafe fn fetch_cap(
		&self,
		src: &CPtr,
		dst: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::FetchCap as i64, src.index() as i64, dst.index() as i64, 0i64, )
	}

	/// Fetches a capability from this capability set to the current task's capability set, with moving semantics.
	pub unsafe fn fetch_cap_move(
		&self,
		src: &CPtr,
		dst: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::FetchCapMove as i64, src.index() as i64, dst.index() as i64, 0i64, )
	}

	/// Returns the type of the capability. The return type is actually `CapType` but needs a conversion.
	pub unsafe fn get_cap_type(
		&self,
		cptr: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::GetCapType as i64, cptr.index() as i64, 0i64, 0i64, )
	}

	/// Makes a leaf entry in this capability set, and initializes it with empty capabilities.
	pub unsafe fn make_leaf(
		&self,
		cptr: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::MakeLeafSet as i64, cptr.index() as i64, 0i64, 0i64, )
	}

	/// Puts a capability from the current task's capability set to this capability set.
	pub unsafe fn put_cap(
		&self,
		src: &CPtr,
		dst: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::PutCap as i64, src.index() as i64, dst.index() as i64, 0i64, )
	}

	/// Puts a capability from the current task's capability set to this capability set, with moving semantics.
	pub unsafe fn put_cap_move(
		&self,
		src: &CPtr,
		dst: &CPtr,
	) -> i64 {
		self.cap.call(CapSetRequest::PutCapMove as i64, src.index() as i64, dst.index() as i64, 0i64, )
	}

}

/// Debugging utility used during early init to print a character to the serial port.
#[derive(Copy, Clone, Debug)]
pub struct DebugPutchar {
    cap: CPtr
}

impl Into<CPtr> for DebugPutchar {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl DebugPutchar {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Prints a character to the serial port.
	pub unsafe fn putchar(
		&self,
		value: u64,
	) -> i64 {
		self.cap.call(value as i64, 0i64, 0i64, 0i64, )
	}

}

/// Capability to an interrupt.
#[derive(Copy, Clone, Debug)]
pub struct Interrupt {
    cap: CPtr
}

impl Into<CPtr> for Interrupt {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl Interrupt {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Binds the interrupt to a task.
	pub unsafe fn bind(
		&self,
		task: &BasicTask,
		pc: u64,
		user_context: u64,
	) -> i64 {
		self.cap.call(InterruptRequest::Bind as i64, task.cptr().index() as i64, pc as i64, user_context as i64, )
	}

}

/// Memory-mapped I/O on one memory page.
#[derive(Copy, Clone, Debug)]
pub struct Mmio {
    cap: CPtr
}

impl Into<CPtr> for Mmio {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl Mmio {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Map the backing physical page into this endpoint's associated page table.
	pub unsafe fn alloc_at(
		&self,
		vaddr: u64,
		prot: UserPteFlags,
	) -> i64 {
		self.cap.call(vaddr as i64, prot.bits() as i64, 0i64, 0i64, )
	}

}

/// Capability to a root page table.
#[derive(Copy, Clone, Debug)]
pub struct RootPageTable {
    cap: CPtr
}

impl Into<CPtr> for RootPageTable {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl RootPageTable {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Allocates a page at a leaf entry in this root page table.
	pub unsafe fn alloc_leaf(
		&self,
		vaddr: u64,
		prot: UserPteFlags,
	) -> i64 {
		self.cap.call(RootPageTableRequest::AllocLeaf as i64, vaddr as i64, prot.bits() as i64, 0i64, )
	}

	/// Drops a page.
	pub unsafe fn drop_page(
		&self,
		target: u64,
	) -> i64 {
		self.cap.call(RootPageTableRequest::DropPage as i64, target as i64, 0i64, 0i64, )
	}

	/// Clones reference to a page in this page table to the current task's page table.
	pub unsafe fn fetch_page(
		&self,
		src: u64,
		dst: u64,
		prot: UserPteFlags,
	) -> i64 {
		self.cap.call(RootPageTableRequest::FetchPage as i64, src as i64, dst as i64, prot.bits() as i64, )
	}

	/// Creates a leaf entry in this root page table, without allocating page for it.
	pub unsafe fn make_leaf(
		&self,
		vaddr: u64,
	) -> i64 {
		self.cap.call(RootPageTableRequest::MakeLeaf as i64, vaddr as i64, 0i64, 0i64, )
	}

	/// Clones reference to a page in the current task's page table to this page table.
	pub unsafe fn put_page(
		&self,
		src: u64,
		dst: u64,
		prot: UserPteFlags,
	) -> i64 {
		self.cap.call(RootPageTableRequest::PutPage as i64, src as i64, dst as i64, prot.bits() as i64, )
	}

	/// Sets protection flags for a page table entry.
	pub unsafe fn set_protection(
		&self,
		target: u64,
		prot: UserPteFlags,
	) -> i64 {
		self.cap.call(RootPageTableRequest::SetProtection as i64, target as i64, prot.bits() as i64, 0i64, )
	}

}

/// The "privileged" root task capability. Hardware capabilities are derived from this.
#[derive(Copy, Clone, Debug)]
pub struct RootTask {
    cap: CPtr
}

impl Into<CPtr> for RootTask {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl RootTask {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Make the current task an idle task. Never returns if succeeded.
	pub unsafe fn make_idle(
		&self,
	) -> i64 {
		self.cap.call(RootTaskCapRequest::MakeIdle as i64, 0i64, 0i64, 0i64, )
	}

	/// Creates a `DebugPutchar` endpoint.
	pub unsafe fn new_debug_putchar(
		&self,
		out: &CPtr,
	) -> i64 {
		self.cap.call(RootTaskCapRequest::DebugPutchar as i64, out.index() as i64, 0i64, 0i64, )
	}

	/// Creates an `Interrupt` endpoint for an interrupt index.
	pub unsafe fn new_interrupt(
		&self,
		out: &CPtr,
		index: u64,
	) -> i64 {
		self.cap.call(RootTaskCapRequest::Interrupt as i64, out.index() as i64, index as i64, 0i64, )
	}

	/// Creates an `Mmio` endpoint for the physical page starting at `phys_addr`.
	pub unsafe fn new_mmio(
		&self,
		out: &CPtr,
		page_table: &RootPageTable,
		phys_addr: u64,
	) -> i64 {
		self.cap.call(RootTaskCapRequest::Mmio as i64, out.index() as i64, page_table.cptr().index() as i64, phys_addr as i64, )
	}

	/// Creates an `X86IoPort` endpoint for a hardware I/O port.
	pub unsafe fn new_x86_io_port(
		&self,
		out: &CPtr,
		port: u64,
	) -> i64 {
		self.cap.call(RootTaskCapRequest::X86IoPort as i64, out.index() as i64, port as i64, 0i64, )
	}

}

/// An IPC endpoint.
#[derive(Copy, Clone, Debug)]
pub struct TaskEndpoint {
    cap: CPtr
}

impl Into<CPtr> for TaskEndpoint {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl TaskEndpoint {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Gets a source-specific tag on the backing task of this IPC endpoint.
	pub unsafe fn get_tag(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::GetTag as i64, 0i64, 0i64, 0i64, )
	}

	/// Invokes the IPC endpoint.
	pub unsafe fn invoke(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::SwitchTo as i64, 0i64, 0i64, 0i64, )
	}

	/// Checks whether this task endpoint has the `CAP_TRANSFER` flag set.
	pub unsafe fn is_cap_transfer(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::IsCapTransfer as i64, 0i64, 0i64, 0i64, )
	}

	/// Checks whether this is a reply endpoint.
	pub unsafe fn is_reply(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::IsReply as i64, 0i64, 0i64, 0i64, )
	}

	/// Checks whether this task endpoint has the `TAGGABLE` flag set.
	pub unsafe fn is_taggable(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::IsTaggable as i64, 0i64, 0i64, 0i64, )
	}

	/// Checks whether the backing task is still alive.
	pub unsafe fn ping(
		&self,
	) -> i64 {
		self.cap.call(IpcRequest::Ping as i64, 0i64, 0i64, 0i64, )
	}

	/// Sets a source-specific tag on the backing task of this IPC endpoint. Requires the `TAGGABLE` flag.
	pub unsafe fn set_tag(
		&self,
		tag: u64,
	) -> i64 {
		self.cap.call(IpcRequest::SetTag as i64, tag as i64, 0i64, 0i64, )
	}

}

/// Capability to an X86 I/O port.
#[derive(Copy, Clone, Debug)]
pub struct X86IoPort {
    cap: CPtr
}

impl Into<CPtr> for X86IoPort {
    fn into(self) -> CPtr {
        self.cap
    }
}

impl X86IoPort {
    pub const unsafe fn new(cap: CPtr) -> Self {
        Self {
            cap,
        }
    }

    pub const fn cptr(&self) -> &CPtr {
        &self.cap
    }

	/// Calls the x86 `inb` instruction on this port.
	pub unsafe fn inb(
		&self,
	) -> i64 {
		self.cap.call(X86IoPortRequest::Read as i64, 1i64, 0i64, 0i64, )
	}

	/// Calls the x86 `outb` instruction on this port.
	pub unsafe fn outb(
		&self,
		value: u64,
	) -> i64 {
		self.cap.call(X86IoPortRequest::Write as i64, 1i64, value as i64, 0i64, )
	}

}
