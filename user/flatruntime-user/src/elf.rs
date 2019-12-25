use goblin::elf::{
    header::header64::Header, program_header::program_header64::ProgramHeader, program_header::*,
};
use crate::mm::RootPageTable;
use crate::error::*;
use crate::allocator::PAGE_SIZE;
use spin::Mutex;
use crate::task::{Task, ROOT_PAGE_TABLE};
use crate::thread::{this_task, ROOT_IPC_BASE};
use crate::layout;
use crate::ipc::{FastIpcPayload, TaskEndpoint};
use crate::syscall::*;

static ELF_PAGE_TEMP_MAP: Mutex<()> = Mutex::new(());

const SP_INDEX: u32 = 7;

trait ReadRaw {
    unsafe fn read_raw<T: Sized + Copy>(&self) -> Option<T>;
}

impl ReadRaw for [u8] {
    unsafe fn read_raw<T: Sized + Copy>(&self) -> Option<T> {
        if self.len() < core::mem::size_of::<T>() {
            None
        } else {
            Some(*(self.as_ptr() as *const T))
        }
    }
}

pub fn build_stack(size: u64, out: &RootPageTable) -> KernelResult<()> {
    let start = layout::STACK_END.checked_sub(size)?;
    if start % (PAGE_SIZE as u64) != 0 {
        return Err(KernelError::InvalidArgument);
    }

    for i in (start..layout::STACK_END).step_by(PAGE_SIZE) {
        out.make_leaf(i as u64)?;
        out.alloc_leaf(i as u64)?;
    }

    Ok(())
}

// FIXME: This function can still panic if `image` is invalid.
pub fn load(image: &[u8], out: &RootPageTable) -> KernelResult<u64> {
    unsafe {
        // This is a no-op if the leaf entry is already created.
        ROOT_PAGE_TABLE.make_leaf(layout::ELF_PAGE_TEMP_MAP_BASE)?;

        let header: Header = image.read_raw()?;
        if header.e_phoff >= image.len() as u64 {
            return Err(KernelError::InvalidArgument);
        }

        let mut segments = &image[header.e_phoff as usize..];
        for _ in 0..header.e_phnum {
            let ph: ProgramHeader = segments.read_raw()?;
            segments = &segments[core::mem::size_of::<ProgramHeader>()..];
            if ph.p_type != PT_LOAD {
                continue;
            }
            let start = ph.p_vaddr as usize;
            if start % PAGE_SIZE != 0 {
                return Err(KernelError::InvalidArgument);
            }
            let end = start.checked_add(ph.p_filesz as usize)?;
            if end - start > image.len() {
                return Err(KernelError::InvalidArgument);
            }
            for i in (start..end).step_by(PAGE_SIZE) {
                let data = &image[(ph.p_offset as usize) + (i - start)..];

                out.make_leaf(i as u64)?;
                out.alloc_leaf(i as u64)?;

                let _guard = ELF_PAGE_TEMP_MAP.lock();
                out.fetch_page(i as u64, layout::ELF_PAGE_TEMP_MAP_BASE)?;
                let slice = core::slice::from_raw_parts_mut(
                    layout::ELF_PAGE_TEMP_MAP_BASE as *mut u8,
                    PAGE_SIZE,
                );
                let copy_end = if end - i < PAGE_SIZE {
                    end - i
                } else {
                    PAGE_SIZE
                };
                slice[..copy_end].copy_from_slice(&data[..copy_end]);
            }
        }
        Ok(header.e_entry)
    }
}

pub fn create_process(image: &[u8], caps: &[(u64, &CPtr)]) -> KernelResult<(Task, TaskEndpoint)> {
    let task = this_task().shallow_clone()?;

    // Initialize page table.
    let new_rpt = this_task().make_root_page_table()?;
    let entry_pc = unsafe {
        load(image, &new_rpt)?
    };
    build_stack(1048576, &new_rpt)?;

    // Initialize capability set.
    let new_capset = this_task().make_capset()?;
    new_capset.make_leaf(0)?;
    new_capset.put_cap(task.cptr(), 0)?;
    for &(p, cptr) in caps {
        // TODO: Allow caps to reside outside of the first endpoint set?
        new_capset.put_cap(cptr, p)?;
    }
    new_capset.make_leaf(ROOT_IPC_BASE)?;

    task.put_capset(&new_capset)?;
    task.put_root_page_table(&new_rpt)?;
    task.set_ipc_base(ROOT_IPC_BASE)?;

    task.set_register(SP_INDEX, layout::STACK_END)?;
    let endpoint = task.fetch_task_cap_transfer_endpoint(entry_pc, 0)?;

    // Initialize.
    endpoint.call(&mut FastIpcPayload::default())?;

    Ok((task, endpoint))
}
