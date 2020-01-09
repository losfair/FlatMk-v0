# Task Endpoint

A task endpoint describes the entry to a task. It contains a reference to the target task, a type along with its associated data, and a set of flags.

There are three types of task endpoints from the kernel perspective:

- Call

A `Call` task endpoint contains the entry address and a 64-bit user-defined context value. Semantically, invoking a `Call` endpoint is similar to calling a function, passing the user-defined context value in the first argument register and the *tag* (described later) in the second argument register.

Depending on the reason of the invocation, either a `CooperativeReply` or `PreemptiveReply` task endpoint to the caller task is put into the first slot in the target task's *IPC capability buffer*.

- CooperativeReply

If a `Call` endpoint is invoked through explicit capability invocation from the caller task, then `CooperativeReply` is the type of the reply endpoint. When invoked, the kernel switches back to the caller task using the syscall calling convention, possibly clobbering some platform-specific registers (`rcx` and `r11` on x86-64).

- PreemptiveReply

If a `Call` endpoint is invoked through a preemption (e.g. interrupts), then `PreemptiveReply` is the type of the reply endpoint. This is same as `CooperativeReply`, except that all general-purpose registers are preserved.

The difference between `CooperativeReply` and `PreemptiveReply` is an implementation detail that exists primarily for optimization, and is invisible to the userspace. The userspace only sees two types of task endpoints, `Call` and `Reply`.

Note that there is another way to create a `CooperativeReply` endpoint and form a call tree instead of a call chain, as described in the [Call Tree](./call-tree.md) section.

A task endpoint can have two possible flags:

- TAGGABLE

The endpoint can be used to add *source-specific* tags to the underlying task. *Source-specific* means that when a caller task adds a tag to another task, the tag is only visible to the caller task. There is a limit on maximum amount of tag sources for each task. Any more attempts to add tags will fail.

- CAP_TRANSFER

When this endpoint is invoked, the caller task's IPC capability buffer will be *moved* to the callee task.

Flags are commutative. A reply endpoint generated as a result of `Call` has the same flags as the `Call` endpoint.
