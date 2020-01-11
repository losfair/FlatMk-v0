//! In-kernel scheduler.

use crate::arch::PAGE_SIZE;
use core::mem::size_of;
use crate::pagealloc::{UniqueKernelPageRef, KernelPageRef};
use crate::kobj::*;
use crate::task::{Task, enter_user_mode_with_registers, StateRestoreMode};
use crate::error::*;
use core::mem::MaybeUninit;
use core::ops::{Index, IndexMut};
use crate::arch::task::{TaskRegisters};
use core::convert::TryFrom;

/// Number of task pages.
/// 
/// With 4-KiB pages we have 512 * 500 = 256000 max running tasks per scheduler.
/// This number is chosen to make a scheduler fit in one page.
const N_TASK_PAGES: usize = 500;

/// Tasks per page.
/// 
/// Determined by platform page size and pointer size (which is 64 bits).
const N_TASKS_PER_PAGE: usize = PAGE_SIZE / size_of::<usize>();

/// Max time slice a task is allowed to run, in nanoseconds.
const MAX_TIME_SLICE: u64 = 2_000_000; // 2 milliseconds

pub struct Scheduler {
    /// The backing task collection.
    tasks: TaskCollection,

    /// Scheduling state.
    state: SchedState,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PreviousTaskStateChange {
    Yield,
    YieldWfi,
    Drop,
}

#[derive(Default)]
struct SchedState {
    /// Index of the head node. (Inclusive)
    head: TaskIndex,

    /// Index of the tail node. (Exclusive)
    tail: TaskIndex,

    /// Current time, in nanoseconds.
    current_time: u64,

    /// The time that the current task started running at, in nanoseconds.
    runstart_time: u64,
}

/// Collection of running tasks.
struct TaskCollection {
    /// Pages that form the run queue.
    task_pages: [UniqueKernelPageRef<TaskPage>; N_TASK_PAGES],
}

/// A task page.
struct TaskPage {
    tasks: [Option<WeakKernelObjectRef<Task>>; N_TASKS_PER_PAGE],
}

/// Index of a task.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
struct TaskIndex {
    /// The index into the `task_pages` array.
    page: u32,

    /// The index in the task page.
    entry: u32,
}

impl Index<TaskIndex> for TaskCollection {
    type Output = Option<WeakKernelObjectRef<Task>>;

    fn index(&self, index: TaskIndex) -> &Self::Output {
        &self.task_pages[index.page as usize].tasks[index.entry as usize]
    }
}

impl IndexMut<TaskIndex> for TaskCollection {
    fn index_mut(&mut self, index: TaskIndex) -> &mut Self::Output {
        &mut self.task_pages[index.page as usize].tasks[index.entry as usize]
    }
}

impl Default for TaskPage {
    fn default() -> Self {
        // Zero is a valid value for `Option<WeakKernelObjectRef<T>>`.
        unsafe {
            core::mem::zeroed()
        }
    }
}

impl TaskCollection {
    fn new() -> TaskCollection {
        unsafe {
            let mut uninit: MaybeUninit<TaskCollection> = MaybeUninit::uninit();
            for page in (*uninit.as_mut_ptr()).task_pages.iter_mut() {
                core::ptr::write(page, UniqueKernelPageRef::try_from(KernelPageRef::new(TaskPage::default()).expect("TaskCollection::new: Cannot allocate page.")).unwrap());
            }
            uninit.assume_init()
        }
    }
}

impl TaskIndex {
    /// Next index.
    /// 
    /// Wraps around.
    fn next(&self) -> TaskIndex {
        if (self.entry + 1) as usize == N_TASKS_PER_PAGE {
            TaskIndex {
                page: if (self.page + 1) as usize == N_TASK_PAGES {
                    0
                } else {
                    self.page + 1
                },
                entry: 0,
            }
        } else {
            TaskIndex {
                page: self.page,
                entry: self.entry + 1,
            }
        }
    }
}

impl Scheduler {
    /// Creates a `Scheduler`.
    pub fn new() -> Scheduler {
        assert!(size_of::<Scheduler>() <= PAGE_SIZE);

        Scheduler {
            tasks: TaskCollection::new(),
            state: SchedState::default(),
        }
    }

    /// The tick function.
    /// 
    /// Adds `time_passed_in_ns` to the time counter and if necessary, reschedule.
    pub fn tick(&mut self, time_passed_in_ns: u64, old_registers: &TaskRegisters, wfi: bool) -> ! {
        self.state.current_time = self.state.current_time.checked_add(time_passed_in_ns).expect("Scheduler::tick: Time overflow.");
        if wfi {
            self.reschedule(old_registers, PreviousTaskStateChange::YieldWfi);
        } else if self.state.current_time - self.state.runstart_time >= MAX_TIME_SLICE {
            self.reschedule(old_registers, PreviousTaskStateChange::Yield);
        } else {
            enter_user_mode_with_registers(StateRestoreMode::Full, old_registers)
        }
    }

    /// Returns the current scheduler time, in nanoseconds.
    pub fn current_time(&self) -> u64 {
        self.state.current_time
    }

    /// Reschedule.
    /// 
    /// Performs task switching if needed, and enters user mode.
    pub fn reschedule(&mut self, old_registers: &TaskRegisters, previous_change: PreviousTaskStateChange) -> ! {
        unsafe {
            if Task::borrow_current().is_interrupt_blocked() {
                println!("Warning: Attempting to reschedule from an interrupt handler.");
                // We cannot reschedule from within an interrupt handler task.
                enter_user_mode_with_registers(StateRestoreMode::Full, old_registers);
            }
        }

        let mut lazy_task_enable = false;

        let current = Task::current(); // shared, reference-counted `current`.

        if previous_change != PreviousTaskStateChange::Drop {
            self.push(current.clone().into()).unwrap();
        } else {
            // FIXME: This is a workaround for `front.id == current.id` never being true
            // if we didn't do `self.push(...)`.
            lazy_task_enable = true;
        }

        for i in 0u64.. {
            if i == 128 {
                println!("Warning: High scheduler latency detected.");
            }
            let front = self.pop().expect("Scheduler::reschedule: Run queue is empty.");
            if let Ok(front) = KernelObjectRef::try_from(front) {
                // A cycle means there are only non-runnable tasks in the queue.
                // Enable lazy tasks in this case.
                if front.id == current.id {
                    lazy_task_enable = true;
                }

                if !lazy_task_enable && front.get_sched_lazy() {
                    self.push(front.into()).unwrap();
                    continue;
                }
                if front.get_nanosleep_deadline() > self.state.current_time {
                    self.push(front.into()).unwrap();
                    continue;
                }
                unsafe {
                    current.local_state().arch_state.will_switch_out();

                    let regs_to_save = if current.local_state().softuser_enabled {
                        None
                    } else {
                        Some(old_registers)
                    };

                    crate::task::switch_to(front, regs_to_save).expect("Scheduler::reschedule: switch_to() failed.");
                }

                // The `current` handle now points to the previous task.
                let prev = current;

                // Lazy flag and IPC blocked flag.
                match previous_change {
                    PreviousTaskStateChange::Yield => {
                        prev.set_sched_lazy(false);
                    }
                    PreviousTaskStateChange::YieldWfi => {
                        prev.set_sched_lazy(true);
                    }
                    PreviousTaskStateChange::Drop => {
                        prev.unblock_ipc().expect("Scheduler::reschedule: Cannot unblock IPC for the previous task.");
                    }
                }

                // Release refcounted handle to the previous task.
                drop(prev);
                
                self.state.runstart_time = self.state.current_time;

                unsafe {
                    Task::borrow_current().local_state().arch_state.did_switch_in();
                }

                // Using `enter_user_mode` here because we need to restore the new task's context.
                crate::task::enter_user_mode(StateRestoreMode::Full);
            } else {
                // The backing task object is dropped. Retry.
            }
        }

        unreachable!()
    }

    /// Pops a task from the run queue.
    fn pop(&mut self) -> Option<WeakKernelObjectRef<Task>> {
        if self.state.head == self.state.tail {
            None
        } else {
            let task = core::mem::replace(&mut self.tasks[self.state.head], None).expect("Scheduler::pop_front: self.state.head != self.state.tail but got empty task");
            self.state.head = self.state.head.next();
            Some(task)
        }
    }

    /// Pushes a task into the run queue.
    /// 
    /// Note that we wasted one entry here - but should be fine.
    pub fn push(&mut self, task: WeakKernelObjectRef<Task>) -> KernelResult<()> {
        if self.state.tail.next() == self.state.head {
            Err(KernelError::OutOfMemory)
        } else {
            assert!(self.tasks[self.state.tail].is_none());
            self.tasks[self.state.tail] = Some(task);
            self.state.tail = self.state.tail.next();
            Ok(())
        }
    }
}