use goblin::elf::{
    header::header64::Header, program_header::program_header64::ProgramHeader, program_header::*,
};
use crate::mm::{UserPteFlags, RootPageTable};
use crate::error::*;
use crate::allocator::PAGE_SIZE;
use spin::Mutex;
use crate::task::*;
use crate::thread::{this_task, ROOT_USER_BASE};
use crate::layout;
use crate::ipc::{FastIpcPayload, TaskEndpoint};
use crate::syscall::*;
use alloc::vec::Vec;

static ELF_PAGE_TEMP_MAP: Mutex<()> = Mutex::new(());

const SP_INDEX: u32 = 7;
const PC_INDEX: u32 = 16;

/// Segment is executable
const PF_X: u32 = 1 << 0;

/// Segment is writable
const PF_W: u32 = 1 << 1;

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
        out.alloc_leaf(i as u64, UserPteFlags::WRITABLE)?;
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

            let mut prot = UserPteFlags::empty();
            if ph.p_flags & PF_W != 0 {
                prot |= UserPteFlags::WRITABLE;
            }
            if ph.p_flags & PF_X != 0 {
                prot |= UserPteFlags::EXECUTABLE;
            }

            for i in (start..end).step_by(PAGE_SIZE) {
                let data = &image[(ph.p_offset as usize) + (i - start)..];

                out.make_leaf(i as u64)?;
                out.alloc_leaf(i as u64, prot)?;

                let _guard = ELF_PAGE_TEMP_MAP.lock();
                out.fetch_page(i as u64, layout::ELF_PAGE_TEMP_MAP_BASE, UserPteFlags::WRITABLE)?;
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

pub fn create_process(image: &[u8], caps: &[(u64, &CPtr)], moving: Vec<(u64, CPtr)>) -> KernelResult<(Task, u64)> {
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
    for (p, cptr) in moving {
        new_capset.put_cap_move(cptr, p)?;
    }

    new_capset.make_leaf(ROOT_USER_BASE)?;

    task.put_capset(&new_capset)?;
    task.put_root_page_table(&new_rpt)?;

    task.set_register(SP_INDEX, layout::STACK_END)?;
    task.set_register(PC_INDEX, entry_pc)?;

    Ok((task, entry_pc))
}

pub fn create_and_initialize_early_process(image: &[u8], caps: &[(u64, &CPtr)], moving: Vec<(u64, CPtr)>) -> KernelResult<()> {
    let (task, entry_pc) = create_process(image, caps, moving)?;
    let endpoint = task.fetch_task_endpoint(entry_pc, 0, TaskEndpointFlags::CAP_TRANSFER, false)?;
    endpoint.call(&mut FastIpcPayload::default())?;
    Ok(())
}

pub fn create_and_prepare_normal_process(image: &[u8], caps: &[(u64, &CPtr)], moving: Vec<(u64, CPtr)>) -> KernelResult<(Task, TaskEndpoint)> {
    let (task, entry_pc) = create_process(image, caps, moving)?;
    let endpoint = task.fetch_task_endpoint(entry_pc, 0, TaskEndpointFlags::TAGGABLE, true)?;
    Ok((task, endpoint))
}
