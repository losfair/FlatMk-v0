# Scheduling and Inter-Process Communication

Note that there is no concept of a "process" in FlatMk, since the only runnable unit is a "task". The name IPC (Inter-Process Communication) is used as a convention.

IPC on the same CPU core is implemented with direct task switching. A [task endpoint](./task-endpoint.md) is needed for switching to the corresponding task. When a task needs to call a service provided by another task, it invokes through capability a task endpoint of type `Call` that points to the target task, which later returns to the previous task by invoking an automatically generated `CooperativeReply` task endpoint. The kernel performs checks to ensure all in-progress IPC calls on a same CPU core are structured as a well-formed [call tree](./call-tree.md).
