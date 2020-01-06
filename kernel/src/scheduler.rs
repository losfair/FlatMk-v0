//! In-kernel scheduler.

use crate::arch::PAGE_SIZE;
use core::mem::size_of;
use crate::pagealloc::KernelPageRef;
use crate::kobj::*;
use crate::task::{Task, StateRestoreMode};
use crate::error::*;
use core::mem::MaybeUninit;
use core::ops::{Index, IndexMut};
use crate::arch::task::{TaskRegisters, arch_enter_user_mode, wait_for_interrupt};
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
    task_pages: [KernelPageRef<TaskPage>; N_TASK_PAGES],
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
                core::ptr::write(page, KernelPageRef::new(TaskPage::default()).expect("TaskCollection::new: Cannot allocate page."));
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
    pub fn tick(&mut self, time_passed_in_ns: u64, old_registers: &TaskRegisters, was_wfi: bool) -> ! {
        self.state.current_time = self.state.current_time.checked_add(time_passed_in_ns).expect("Scheduler::tick: Time overflow.");
        if was_wfi || self.state.current_time - self.state.runstart_time >= MAX_TIME_SLICE {
            self.reschedule(old_registers);
        } else {
            unsafe {
                arch_enter_user_mode(old_registers)
            }
        }
    }

    /// Returns the current scheduler time, in nanoseconds.
    pub fn current_time(&self) -> u64 {
        self.state.current_time
    }

    /// Reschedule.
    /// 
    /// Performs task switching if needed, and enters user mode.
    pub fn reschedule(&mut self, old_registers: &TaskRegisters) -> ! {
        let mut first_nanosleep_id_seen: Option<u64> = None;

        // Place a limit on max retry count to ensure an upper bound on scheduler latency.
        for _ in 0..64 {
            if let Some(front) = self.pop() {
                // We got a task from the run queue. Try switching to it, or retry the loop.

                if let Ok(front) = KernelObjectRef::try_from(front) {
                    if front.get_nanosleep_deadline() > self.state.current_time {
                        let front_id = front.id;
                        self.push(front.into()).expect("Scheduler::reschedule: Popped a task but cannot push another task.");

                        // A cycle means there are only non-runnable tasks in the queue. Break.
                        match first_nanosleep_id_seen {
                            Some(x) => {
                                if x == front_id {
                                    break;
                                }
                            }
                            None => {
                                first_nanosleep_id_seen = Some(front_id);
                            }
                        }

                        continue;
                    }
                    unsafe {
                        (*Task::borrow_current().local_state.unsafe_deref()).arch_state.will_switch_out();
                    }

                    let maybe_prev = unsafe {
                        crate::task::switch_to(front, Some(old_registers))
                    };
                    match maybe_prev {
                        Ok(Some(prev)) => {
                            // Save the previous task, update time, and enter user mode.
                            self.push(prev.into()).expect("Scheduler::reschedule: Popped a task but cannot push another task.");
                            self.state.runstart_time = self.state.current_time;

                            unsafe {
                                (*Task::borrow_current().local_state.unsafe_deref()).arch_state.did_switch_in();
                            }

                            // Using `enter_user_mode` here because we need to restore the new task's context.
                            crate::task::enter_user_mode(StateRestoreMode::Full);
                        }
                        Ok(None) => {
                            // Impossible.
                            unreachable!();
                        },
                        Err(_) => {
                            // Retry,
                        }
                    }
                } else {
                    // The backing task object is dropped. Retry.
                }
            } else {
                // Nothing to switch to.
                break;
            }
        }

        // Nothing can be switched to. Return to the current task.
        // If even the current task cannot be run (in nanosleep), then enter WFI.
        unsafe {
            if Task::borrow_current().get_nanosleep_deadline() > self.state.current_time {
                // We need to save the current registers before entering WFI.
                let registers = &mut (*Task::borrow_current().local_state.unsafe_deref()).registers;
                *registers = old_registers.clone();
                registers.lazy_read();
                wait_for_interrupt();
            } else {
                arch_enter_user_mode(old_registers);
            }
        }
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