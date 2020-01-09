# Core Concepts

## Capabilities

A capability is a non-forgeable descriptor that describes a system resource, and is the only userspace entry to the kernel.

## Multilevel Tables

A multilevel table is a generic data structure that defines a tree with fixed depth and fixed node size. It is used to implement capability tables and page tables.

## Tasks

In FlatMk, a task is the runnable unit that contains its own scheduling context, page table and capability table, along with several state flags. A task alone does not have many properties

## Kernel Objects

A kernel object is a reference-counted container for different types, including tasks and multilevel tables. The in-memory size of each kernel object is fixed to the page size.
