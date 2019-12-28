// This file is generated by flatmk-codegen. Do not edit.

#[allow(unused_imports)]
use num_enum::TryFromPrimitive;

/// A request to a BasicTask/BasicTaskWeak endpoint.
#[repr(i64)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum BasicTaskRequest {
	Ping = 0,
	FetchShallowClone = 1,
	FetchCapSet = 2,
	FetchRootPageTable = 3,
	GetRegister = 4,
	SetRegister = 5,
	FetchTaskEndpoint = 6,
	FetchIpcCap = 7,
	PutIpcCap = 8,
	PutCapSet = 9,
	MakeCapSet = 10,
	MakeRootPageTable = 11,
	PutRootPageTable = 12,
	IpcReturn = 13,
	FetchWeak = 14,
	HasWeak = 15,
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
}

