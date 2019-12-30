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

