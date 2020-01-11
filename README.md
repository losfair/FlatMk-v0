# FlatMk

The FlatMk microkernel, version 0.

This project is mostly for experimenting with microkernels and OSes and gathering experience. Work on FlatMk v1 is in progress but I
plan to make it public only after a sufficient amount of progress has been made.

## Performance

```

Coffee Lake, PCID disabled
Benchmark: IPC w/o PT switch
benchmark: 1116 cycles per op
Benchmark: IPC w/ PT switch to SHMEM daemon (CAP_TRANSFER)
benchmark: 2081 cycles per op
Benchmark: Scheduler yield
benchmark: 776 cycles per op
Benchmark: Softuser enter/leave
benchmark: 926 cycles per op
Benchmark: IPC w/o PT switch to softuser
benchmark: 1390 cycles per op
Benchmark: IPC w/ PT switch to softuser
benchmark: 2061 cycles per op

Coffee Lake, PCID enabled
Benchmark: IPC w/o PT switch
benchmark: 1112 cycles per op
Benchmark: IPC w/ PT switch to SHMEM daemon (CAP_TRANSFER)
benchmark: 1787 cycles per op
Benchmark: Scheduler yield
benchmark: 775 cycles per op
Benchmark: Softuser enter/leave
benchmark: 892 cycles per op
Benchmark: IPC w/o PT switch to softuser
benchmark: 1356 cycles per op
Benchmark: IPC w/ PT switch to softuser
benchmark: 1750 cycles per op

Skylake, PCID disabled
Benchmark: IPC w/o PT switch
benchmark: 1533 cycles per op
Benchmark: IPC w/ PT switch to SHMEM daemon (CAP_TRANSFER)
benchmark: 2528 cycles per op
Benchmark: Scheduler yield
benchmark: 1057 cycles per op
Benchmark: Softuser enter/leave
benchmark: 1265 cycles per op
Benchmark: IPC w/o PT switch to softuser
benchmark: 1839 cycles per op
Benchmark: IPC w/ PT switch to softuser
benchmark: 2498 cycles per op

Skylake, PCID enabled
Benchmark: IPC w/o PT switch
benchmark: 1530 cycles per op
Benchmark: IPC w/ PT switch to SHMEM daemon (CAP_TRANSFER)
benchmark: 2411 cycles per op
Benchmark: Scheduler yield
benchmark: 1058 cycles per op
Benchmark: Softuser enter/leave
benchmark: 1211 cycles per op
Benchmark: IPC w/o PT switch to softuser
benchmark: 1851 cycles per op
Benchmark: IPC w/ PT switch to softuser
benchmark: 2326 cycles per op

```