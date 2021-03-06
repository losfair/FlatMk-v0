// This file is generated by flatmk-codegen. Do not edit.

// A request to a BasicTask/BasicTaskWeak endpoint.
enum BasicTaskRequest {
	BasicTaskRequest_Ping = 0,
	BasicTaskRequest_FetchShallowClone = 1,
	BasicTaskRequest_FetchCapSet = 2,
	BasicTaskRequest_FetchRootPageTable = 3,
	BasicTaskRequest_FetchWeak = 4,
	BasicTaskRequest_FetchTaskEndpoint = 5,
	BasicTaskRequest_FetchIpcCap = 6,
	BasicTaskRequest_PutIpcCap = 7,
	BasicTaskRequest_PutCapSet = 8,
	BasicTaskRequest_PutRootPageTable = 9,
	BasicTaskRequest_MakeCapSet = 10,
	BasicTaskRequest_MakeRootPageTable = 11,
	BasicTaskRequest_SetRegister = 12,
	BasicTaskRequest_HasWeak = 13,
	BasicTaskRequest_IpcReturn = 14,
	BasicTaskRequest_PutFaultHandler = 15,
	BasicTaskRequest_GetAllRegisters = 16,
	BasicTaskRequest_SetAllRegisters = 17,
	BasicTaskRequest_SetSyscallDelegated = 18,
	BasicTaskRequest_GetAllSoftuserRegisters = 19,
	BasicTaskRequest_SetAllSoftuserRegisters = 20,
};

// A key to a boot parameter.
enum BootParameterKey {
	BootParameterKey_FramebufferInfo = 0,
};

// A request to a capability set.
enum CapSetRequest {
	CapSetRequest_MakeLeafSet = 0,
	CapSetRequest_CloneCap = 1,
	CapSetRequest_DropCap = 2,
	CapSetRequest_FetchCap = 3,
	CapSetRequest_PutCap = 4,
	CapSetRequest_MoveCap = 6,
	CapSetRequest_GetCapType = 7,
	CapSetRequest_FetchCapMove = 8,
	CapSetRequest_PutCapMove = 9,
};

// The type of a capability endpoint.
enum CapType {
	CapType_Other = 0,
	CapType_TaskEndpoint = 1,
	CapType_RootPageTable = 2,
};

// A request to an interrupt endpoint.
enum InterruptRequest {
	InterruptRequest_Bind = 0,
	InterruptRequest_Unbind = 1,
};

// A request to an IPC endpoint for another task.
enum IpcRequest {
	IpcRequest_SwitchTo = 0,
	IpcRequest_IsCapTransfer = 1,
	IpcRequest_IsTaggable = 2,
	IpcRequest_IsReply = 3,
	IpcRequest_SetTag = 4,
	IpcRequest_GetTag = 5,
	IpcRequest_Ping = 6,
};

// Kernel error codes.
enum KernelError {
	KernelError_OutOfMemory = -8,
	KernelError_InvalidReference = -7,
	KernelError_EmptyCapability = -6,
	KernelError_EmptyObject = -5,
	KernelError_InvalidAddress = -4,
	KernelError_InvalidState = -3,
	KernelError_NotImplemented = -2,
	KernelError_InvalidArgument = -1,
};

// A request to a root page table.
enum RootPageTableRequest {
	RootPageTableRequest_MakeLeaf = 0,
	RootPageTableRequest_AllocLeaf = 1,
	RootPageTableRequest_PutPage = 2,
	RootPageTableRequest_FetchPage = 3,
	RootPageTableRequest_DropPage = 4,
	RootPageTableRequest_SetProtection = 5,
};

// A request to the root capability.
enum RootTaskCapRequest {
	RootTaskCapRequest_X86IoPort = 0,
	RootTaskCapRequest_Mmio = 1,
	RootTaskCapRequest_Interrupt = 2,
	RootTaskCapRequest_DebugPutchar = 3,
	RootTaskCapRequest_GetBootParameter = 4,
};

// Reason of a fault from a user-mode task.
enum TaskFaultReason {
	TaskFaultReason_VMAccess = 0,
	TaskFaultReason_IllegalInstruction = 1,
	TaskFaultReason_InvalidCapability = 2,
	TaskFaultReason_InvalidOperation = 3,
};

// A trivial syscall that is not invoked on a capability.
enum TrivialSyscall {
	TrivialSyscall_SchedYield = 0,
	TrivialSyscall_SchedDrop = 1,
	TrivialSyscall_SchedNanosleep = 2,
	TrivialSyscall_SchedSubmit = 3,
	TrivialSyscall_SoftuserEnter = 4,
	TrivialSyscall_SoftuserLeave = 5,
};

// A request to an X86 I/O port.
enum X86IoPortRequest {
	X86IoPortRequest_Read = 0,
	X86IoPortRequest_Write = 1,
};

// Flags for a task endpoint.
#define TaskEndpointFlags_CAP_TRANSFER (1 << 0)
#define TaskEndpointFlags_TAGGABLE (1 << 1)

// Flags for a user page table entry.
#define UserPteFlags_WRITABLE (1 << 0)
#define UserPteFlags_EXECUTABLE (1 << 1)

// A strong or weak reference to a task.
struct BasicTask {
    CPtr cap;
};

static inline struct BasicTask BasicTask_new(CPtr cap) {
    struct BasicTask result = { .cap = cap };
    return result;
}
// A capability set.
struct CapabilitySet {
    CPtr cap;
};

static inline struct CapabilitySet CapabilitySet_new(CPtr cap) {
    struct CapabilitySet result = { .cap = cap };
    return result;
}
// Debugging utility used during early init to print a character to the serial port.
struct DebugPutchar {
    CPtr cap;
};

static inline struct DebugPutchar DebugPutchar_new(CPtr cap) {
    struct DebugPutchar result = { .cap = cap };
    return result;
}
// Capability to an interrupt.
struct Interrupt {
    CPtr cap;
};

static inline struct Interrupt Interrupt_new(CPtr cap) {
    struct Interrupt result = { .cap = cap };
    return result;
}
// Memory-mapped I/O on one memory page.
struct Mmio {
    CPtr cap;
};

static inline struct Mmio Mmio_new(CPtr cap) {
    struct Mmio result = { .cap = cap };
    return result;
}
// Capability to a root page table.
struct RootPageTable {
    CPtr cap;
};

static inline struct RootPageTable RootPageTable_new(CPtr cap) {
    struct RootPageTable result = { .cap = cap };
    return result;
}
// The "privileged" root task capability. Hardware capabilities are derived from this.
struct RootTask {
    CPtr cap;
};

static inline struct RootTask RootTask_new(CPtr cap) {
    struct RootTask result = { .cap = cap };
    return result;
}
// An IPC endpoint.
struct TaskEndpoint {
    CPtr cap;
};

static inline struct TaskEndpoint TaskEndpoint_new(CPtr cap) {
    struct TaskEndpoint result = { .cap = cap };
    return result;
}
// Entry to trivial syscalls. Only valid on capability pointer `u64::MAX`.
struct TrivialSyscallEntry {
    CPtr cap;
};

static inline struct TrivialSyscallEntry TrivialSyscallEntry_new(CPtr cap) {
    struct TrivialSyscallEntry result = { .cap = cap };
    return result;
}
// Capability to an X86 I/O port.
struct X86IoPort {
    CPtr cap;
};

static inline struct X86IoPort X86IoPort_new(CPtr cap) {
    struct X86IoPort result = { .cap = cap };
    return result;
}
// Invokes an invalid operation on this capability. Useful for benchmarking.
static inline int64_t BasicTask_call_invalid(
	struct BasicTask me
) {
	return cptr_invoke(me.cap, -1ll, 0ll, 0ll, 0ll);
}

// Fetch the capability set of this task into the current task's capability set.
static inline int64_t BasicTask_fetch_capset(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchCapSet, out, 0ll, 0ll);
}

// Fetches a capability from the IPC capability buffer of this task. The capability is moved instead of cloned.
static inline int64_t BasicTask_fetch_ipc_cap(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out,
	// An index to the capability buffer.
	uint64_t index
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchIpcCap, out, index, 0ll);
}

// Fetch the root page table of this task into the current task's capability set.
static inline int64_t BasicTask_fetch_root_page_table(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchRootPageTable, out, 0ll, 0ll);
}

// Makes a shallow clone for this task. The clone will always be a strong reference.
// 
// The resulting task shares the same capability set and page table with this task, but has its own state flags and execution context.
static inline int64_t BasicTask_fetch_shallow_clone(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchShallowClone, out, 0ll, 0ll);
}

// Fetches an IPC endpoint to this task.
// 
// The first argument `mixed_arg1` is a mixed argument that contains several properties:
// 
// - Bits 0 to 47 (inclusively) is a capability pointer in the current task's capability set to write to.
// - Bits 48 to 62 is a bitflag set of type `TaskEndpointFlags`.
// - Bit 63 indicates whether the new endpoint is a reply endpoint.
static inline int64_t BasicTask_fetch_task_endpoint(
	struct BasicTask me,
	// The mixed argument.
	uint64_t mixed_arg1,
	// Program Counter/Instruction Pointer value for the IPC entry.
	uint64_t pc,
	// User context for the IPC entry.
	uint64_t user_context
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchTaskEndpoint, mixed_arg1, pc, user_context);
}

// Makes a weak reference for this task.
static inline int64_t BasicTask_fetch_weak(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_FetchWeak, out, 0ll, 0ll);
}

// Gets all registers of this task.
static inline int64_t BasicTask_get_all_registers(
	struct BasicTask me,
	// Pointer to write to.
	uint64_t ptr,
	// Length of the memory `ptr` points to.
	uint64_t len
) {
	return cptr_invoke(me.cap, BasicTaskRequest_GetAllRegisters, ptr, len, 0ll);
}

// Gets all softuser registers of this task.
static inline int64_t BasicTask_get_all_softuser_registers(
	struct BasicTask me,
	// Pointer to write to.
	uint64_t ptr,
	// Length of the memory `ptr` points to.
	uint64_t len
) {
	return cptr_invoke(me.cap, BasicTaskRequest_GetAllSoftuserRegisters, ptr, len, 0ll);
}

// Returns whether there exists weak references to this task.
static inline int64_t BasicTask_has_weak(
	struct BasicTask me
) {
	return cptr_invoke(me.cap, BasicTaskRequest_HasWeak, 0ll, 0ll, 0ll);
}

// Fast path for returning from an IPC call, by automatically invoking the 0th entry in this task's IPC capability buffer.
static inline int64_t BasicTask_ipc_return(
	struct BasicTask me
) {
	return cptr_invoke(me.cap, BasicTaskRequest_IpcReturn, 0ll, 0ll, 0ll);
}

// Makes a capability set and puts its endpoint in the current task's capability set. (FIXME: Maybe this shouldn't be in BasicTask?)
static inline int64_t BasicTask_make_capset(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_MakeCapSet, out, 0ll, 0ll);
}

// Makes a root page table and puts its endpoint in the current task's capability set. (FIXME: Maybe this shouldn't be in BasicTask?)
static inline int64_t BasicTask_make_root_page_table(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, BasicTaskRequest_MakeRootPageTable, out, 0ll, 0ll);
}

// Detects whether the reference is still alive if it is a weak reference. Always return 0 for strong references.
static inline int64_t BasicTask_ping(
	struct BasicTask me
) {
	return cptr_invoke(me.cap, BasicTaskRequest_Ping, 0ll, 0ll, 0ll);
}

// Puts an endpoint to a capability set in the current task's capability set into this task's capability set.
static inline int64_t BasicTask_put_capset(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to read from.
	struct CapabilitySet cptr
) {
	return cptr_invoke(me.cap, BasicTaskRequest_PutCapSet, cptr.cap, 0ll, 0ll);
}

// Sets the fault handler of this task.
static inline int64_t BasicTask_put_fault_handler(
	struct BasicTask me,
	// The endpoint to the handler. Must have a `Call` entry type.
	struct TaskEndpoint handler
) {
	return cptr_invoke(me.cap, BasicTaskRequest_PutFaultHandler, handler.cap, 0ll, 0ll);
}

// Puts a capability into the IPC capability buffer of this task. The capability is moved instead of cloned.
static inline int64_t BasicTask_put_ipc_cap(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to read from.
	CPtr cptr,
	// An index to the capability buffer.
	uint64_t index
) {
	return cptr_invoke(me.cap, BasicTaskRequest_PutIpcCap, cptr, index, 0ll);
}

// Puts an endpoint to a root page table in the current task's capability set into this task's capability set.
static inline int64_t BasicTask_put_root_page_table(
	struct BasicTask me,
	// A capability pointer in the current task's capability set to read from.
	struct RootPageTable cptr
) {
	return cptr_invoke(me.cap, BasicTaskRequest_PutRootPageTable, cptr.cap, 0ll, 0ll);
}

// Sets all registers of this task.
static inline int64_t BasicTask_set_all_registers(
	struct BasicTask me,
	// Pointer to read from.
	uint64_t ptr,
	// Length of the memory `ptr` points to.
	uint64_t len
) {
	return cptr_invoke(me.cap, BasicTaskRequest_SetAllRegisters, ptr, len, 0ll);
}

// Sets all softuser registers of this task.
static inline int64_t BasicTask_set_all_softuser_registers(
	struct BasicTask me,
	// Pointer to read from.
	uint64_t ptr,
	// Length of the memory `ptr` points to.
	uint64_t len
) {
	return cptr_invoke(me.cap, BasicTaskRequest_SetAllSoftuserRegisters, ptr, len, 0ll);
}

// Sets a saved register of this task. Calling this method on a running task has undefined result.
static inline int64_t BasicTask_set_register(
	struct BasicTask me,
	// The DWARF index for the target register.
	uint64_t index,
	// The value to set the register to.
	uint64_t value
) {
	return cptr_invoke(me.cap, BasicTaskRequest_SetRegister, index, value, 0ll);
}

// Sets the syscall delegation status of this task.
static inline int64_t BasicTask_set_syscall_delegated(
	struct BasicTask me,
	// A boolean value indicating whether to enable syscall delegation.
	uint64_t status
) {
	return cptr_invoke(me.cap, BasicTaskRequest_SetSyscallDelegated, status, 0ll, 0ll);
}

// Clones a capability.
static inline int64_t CapabilitySet_clone_cap(
	struct CapabilitySet me,
	// Source capability pointer.
	CPtr src,
	// Destination capability pointer.
	CPtr dst
) {
	return cptr_invoke(me.cap, CapSetRequest_CloneCap, src, dst, 0ll);
}

// Drops a capability.
static inline int64_t CapabilitySet_drop_cap(
	struct CapabilitySet me,
	// The capability pointer that points to the target capability.
	CPtr cptr
) {
	return cptr_invoke(me.cap, CapSetRequest_DropCap, cptr, 0ll, 0ll);
}

// Fetches a capability from this capability set to the current task's capability set.
static inline int64_t CapabilitySet_fetch_cap(
	struct CapabilitySet me,
	// Source capability pointer.
	CPtr src,
	// Destination capability pointer.
	CPtr dst
) {
	return cptr_invoke(me.cap, CapSetRequest_FetchCap, src, dst, 0ll);
}

// Fetches a capability from this capability set to the current task's capability set, with moving semantics.
static inline int64_t CapabilitySet_fetch_cap_move(
	struct CapabilitySet me,
	// Source capability pointer.
	CPtr src,
	// Destination capability pointer.
	CPtr dst
) {
	return cptr_invoke(me.cap, CapSetRequest_FetchCapMove, src, dst, 0ll);
}

// Returns the type of the capability. The return type is actually `CapType` but needs a conversion.
static inline int64_t CapabilitySet_get_cap_type(
	struct CapabilitySet me,
	// The capability pointer that points to the target capability.
	CPtr cptr
) {
	return cptr_invoke(me.cap, CapSetRequest_GetCapType, cptr, 0ll, 0ll);
}

// Makes a leaf entry in this capability set, and initializes it with empty capabilities.
static inline int64_t CapabilitySet_make_leaf(
	struct CapabilitySet me,
	// The "base" capability pointer that points to the entry.
	CPtr cptr
) {
	return cptr_invoke(me.cap, CapSetRequest_MakeLeafSet, cptr, 0ll, 0ll);
}

// Puts a capability from the current task's capability set to this capability set.
static inline int64_t CapabilitySet_put_cap(
	struct CapabilitySet me,
	// Source capability pointer.
	CPtr src,
	// Destination capability pointer.
	CPtr dst
) {
	return cptr_invoke(me.cap, CapSetRequest_PutCap, src, dst, 0ll);
}

// Puts a capability from the current task's capability set to this capability set, with moving semantics.
static inline int64_t CapabilitySet_put_cap_move(
	struct CapabilitySet me,
	// Source capability pointer.
	CPtr src,
	// Destination capability pointer.
	CPtr dst
) {
	return cptr_invoke(me.cap, CapSetRequest_PutCapMove, src, dst, 0ll);
}

// Prints a character to the serial port.
static inline int64_t DebugPutchar_putchar(
	struct DebugPutchar me,
	// The 8-bit character to print.
	uint64_t value
) {
	return cptr_invoke(me.cap, value, 0ll, 0ll, 0ll);
}

// Binds the interrupt to a task.
static inline int64_t Interrupt_bind(
	struct Interrupt me,
	// The task to bind to.
	struct BasicTask task,
	// Program Counter/Instruction Pointer value for the IPC entry.
	uint64_t pc,
	// User context for the IPC entry.
	uint64_t user_context
) {
	return cptr_invoke(me.cap, InterruptRequest_Bind, task.cap, pc, user_context);
}

// Map the backing physical page into this endpoint's associated page table.
static inline int64_t Mmio_alloc_at(
	struct Mmio me,
	// The target virtual address.
	uint64_t vaddr,
	// Protection flags.
	uint64_t prot
) {
	return cptr_invoke(me.cap, vaddr, prot, 0ll, 0ll);
}

// Allocates a page at a leaf entry in this root page table. Will also create the leaf entry if not exists.
static inline int64_t RootPageTable_alloc_leaf(
	struct RootPageTable me,
	uint64_t vaddr,
	uint64_t prot
) {
	return cptr_invoke(me.cap, RootPageTableRequest_AllocLeaf, vaddr, prot, 0ll);
}

// Drops a page.
static inline int64_t RootPageTable_drop_page(
	struct RootPageTable me,
	uint64_t target
) {
	return cptr_invoke(me.cap, RootPageTableRequest_DropPage, target, 0ll, 0ll);
}

// Clones reference to a page in this page table to the current task's page table. Will also create the leaf entry if not exists.
static inline int64_t RootPageTable_fetch_page(
	struct RootPageTable me,
	uint64_t src,
	uint64_t dst,
	uint64_t prot
) {
	return cptr_invoke(me.cap, RootPageTableRequest_FetchPage, src, dst, prot);
}

// Creates a leaf entry in this root page table, without allocating page for it.
static inline int64_t RootPageTable_make_leaf(
	struct RootPageTable me,
	uint64_t vaddr
) {
	return cptr_invoke(me.cap, RootPageTableRequest_MakeLeaf, vaddr, 0ll, 0ll);
}

// Clones reference to a page in the current task's page table to this page table. Will also create the leaf entry if not exists.
static inline int64_t RootPageTable_put_page(
	struct RootPageTable me,
	uint64_t src,
	uint64_t dst,
	uint64_t prot
) {
	return cptr_invoke(me.cap, RootPageTableRequest_PutPage, src, dst, prot);
}

// Sets protection flags for a page table entry.
static inline int64_t RootPageTable_set_protection(
	struct RootPageTable me,
	uint64_t target,
	uint64_t prot
) {
	return cptr_invoke(me.cap, RootPageTableRequest_SetProtection, target, prot, 0ll);
}

// Reads the boot parameter of key `key`. Returns 0 on succeed, negative error code on failure.
static inline int64_t RootTask_get_boot_parameter(
	struct RootTask me,
	// The key to the requested parameter. Is of type `BootParameterKey`.
	int64_t key,
	// Output address.
	uint64_t out,
	// Length of the memory block `out` points to.
	uint64_t out_len
) {
	return cptr_invoke(me.cap, RootTaskCapRequest_GetBootParameter, key, out, out_len);
}

// Creates a `DebugPutchar` endpoint.
static inline int64_t RootTask_new_debug_putchar(
	struct RootTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out
) {
	return cptr_invoke(me.cap, RootTaskCapRequest_DebugPutchar, out, 0ll, 0ll);
}

// Creates an `Interrupt` endpoint for an interrupt index.
static inline int64_t RootTask_new_interrupt(
	struct RootTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out,
	// The associated interrupt index.
	uint64_t index
) {
	return cptr_invoke(me.cap, RootTaskCapRequest_Interrupt, out, index, 0ll);
}

// Creates an `Mmio` endpoint for the physical page starting at `phys_addr`.
static inline int64_t RootTask_new_mmio(
	struct RootTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out,
	// The page table that the physical page will be mapped into.
	struct RootPageTable page_table,
	// The physical address.
	uint64_t phys_addr
) {
	return cptr_invoke(me.cap, RootTaskCapRequest_Mmio, out, page_table.cap, phys_addr);
}

// Creates an `X86IoPort` endpoint for a hardware I/O port.
static inline int64_t RootTask_new_x86_io_port(
	struct RootTask me,
	// A capability pointer in the current task's capability set to write to.
	CPtr out,
	// The associated port.
	uint64_t port
) {
	return cptr_invoke(me.cap, RootTaskCapRequest_X86IoPort, out, port, 0ll);
}

// Gets a source-specific tag on the backing task of this IPC endpoint.
static inline int64_t TaskEndpoint_get_tag(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_GetTag, 0ll, 0ll, 0ll);
}

// Invokes the IPC endpoint.
static inline int64_t TaskEndpoint_invoke(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_SwitchTo, 0ll, 0ll, 0ll);
}

// Checks whether this task endpoint has the `CAP_TRANSFER` flag set.
static inline int64_t TaskEndpoint_is_cap_transfer(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_IsCapTransfer, 0ll, 0ll, 0ll);
}

// Checks whether this is a reply endpoint.
static inline int64_t TaskEndpoint_is_reply(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_IsReply, 0ll, 0ll, 0ll);
}

// Checks whether this task endpoint has the `TAGGABLE` flag set.
static inline int64_t TaskEndpoint_is_taggable(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_IsTaggable, 0ll, 0ll, 0ll);
}

// Checks whether the backing task is still alive.
static inline int64_t TaskEndpoint_ping(
	struct TaskEndpoint me
) {
	return cptr_invoke(me.cap, IpcRequest_Ping, 0ll, 0ll, 0ll);
}

// Sets a source-specific tag on the backing task of this IPC endpoint. Requires the `TAGGABLE` flag.
static inline int64_t TaskEndpoint_set_tag(
	struct TaskEndpoint me,
	// The value of the new tag.
	uint64_t tag
) {
	return cptr_invoke(me.cap, IpcRequest_SetTag, tag, 0ll, 0ll);
}

// Drops the current task from the scheduler.
static inline int64_t TrivialSyscallEntry_sched_drop(
	struct TrivialSyscallEntry me
) {
	return cptr_invoke(me.cap, TrivialSyscall_SchedDrop, 0ll, 0ll, 0ll);
}

// Put the current task to sleep.
static inline int64_t TrivialSyscallEntry_sched_nanosleep(
	struct TrivialSyscallEntry me,
	// Duration in nanoseconds.
	uint64_t duration
) {
	return cptr_invoke(me.cap, TrivialSyscall_SchedNanosleep, duration, 0ll, 0ll);
}

// Submits a scheduling endpoint.
static inline int64_t TrivialSyscallEntry_sched_submit(
	struct TrivialSyscallEntry me,
	// Reply endpoint to submit.
	struct TaskEndpoint target
) {
	return cptr_invoke(me.cap, TrivialSyscall_SchedSubmit, target.cap, 0ll, 0ll);
}

// Yields from the current task to allow other tasks to run.
static inline int64_t TrivialSyscallEntry_sched_yield(
	struct TrivialSyscallEntry me
) {
	return cptr_invoke(me.cap, TrivialSyscall_SchedYield, 0ll, 0ll, 0ll);
}

// Enters softuser mode.
static inline int64_t TrivialSyscallEntry_softuser_enter(
	struct TrivialSyscallEntry me,
	// Program counter value to start execution from.
	uint64_t pc
) {
	return cptr_invoke(me.cap, TrivialSyscall_SoftuserEnter, pc, 0ll, 0ll);
}

// Leaves softuser mode.
static inline int64_t TrivialSyscallEntry_softuser_leave(
	struct TrivialSyscallEntry me
) {
	return cptr_invoke(me.cap, TrivialSyscall_SoftuserLeave, 0ll, 0ll, 0ll);
}

// Calls the x86 `inb` instruction on this port.
static inline int64_t X86IoPort_inb(
	struct X86IoPort me
) {
	return cptr_invoke(me.cap, X86IoPortRequest_Read, 1ll, 0ll, 0ll);
}

// Calls the x86 `outb` instruction on this port.
static inline int64_t X86IoPort_outb(
	struct X86IoPort me,
	// The 8-bit value to write.
	uint64_t value
) {
	return cptr_invoke(me.cap, X86IoPortRequest_Write, 1ll, value, 0ll);
}

