#![no_std]

use flatmk_sys::spec::{self, KernelError};
use goblin::elf::{
    header::header64::Header, program_header::program_header64::ProgramHeader, program_header::*,
};
use spin::Mutex;

/// DWARF index of SP on x86-64.
const SP_INDEX: u64 = 7;

/// DWARF index of PC on x86-64.
const PC_INDEX: u64 = 16;

/// Segment is executable.
const PF_X: u32 = 1 << 0;

/// Segment is writable.
const PF_W: u32 = 1 << 1;

/// Read raw bytes into a typed value.
trait ReadRaw {
    /// Perform the read. Unsafe because the caller needs to ensure that any bit pattern
    /// will be a valid `T`.
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

/// Address for temporarily mapping one page during ELF load.
pub struct ElfTempMapBase(Mutex<u64>);

impl ElfTempMapBase {
    /// Creates an `ElfTempMapBase`.
    /// 
    /// Unsafe because the caller needs to ensure that `base` points to a valid, unused
    /// page in the current task's virtual address space.
    pub const unsafe fn new(base: u64) -> ElfTempMapBase {
        ElfTempMapBase(Mutex::new(base))
    }

    /// Makes the leaf entry.
    pub fn make_leaf(&self, pt: &spec::RootPageTable) -> Result<(), KernelError> {
        let addr = self.0.lock();
        unsafe {
            spec::to_result(pt.make_leaf(*addr))?;
        }
        Ok(())
    }
}

/// ELF image metadata.
#[derive(Clone, Debug)]
pub struct ElfMetadata {
    /// The entry virtual address.
    pub entry_address: u64,
}

impl ElfMetadata {
    pub fn apply_to_task(&self, task: &spec::BasicTask) -> Result<(), KernelError> {
        unsafe {
            spec::to_result(task.set_register(PC_INDEX, self.entry_address))?;
        }
        Ok(())
    }
}

/// Loads an image into `out`.
/// 
/// The leaf entry of `temp_base` must first be built.
pub fn load(image: &[u8], temp_base: &ElfTempMapBase, out: &spec::RootPageTable) -> Result<ElfMetadata, KernelError> {
    unsafe {
        let header: Header = match image.read_raw() {
            Some(x) => x,
            None => return Err(KernelError::InvalidArgument),
        };
        if header.e_phoff >= image.len() as u64 {
            return Err(KernelError::InvalidArgument);
        }

        let mut segments = &image[header.e_phoff as usize..];
        for _ in 0..header.e_phnum {
            let ph: ProgramHeader = match segments.read_raw() {
                Some(x) => x,
                None => return Err(KernelError::InvalidArgument),
            };
            segments = &segments[core::mem::size_of::<ProgramHeader>()..];
            if ph.p_type != PT_LOAD {
                continue;
            }
            let start = ph.p_vaddr as usize;
            if start % spec::PAGE_SIZE != 0 {
                return Err(KernelError::InvalidArgument);
            }
            let mem_end = match start.checked_add(ph.p_memsz as usize) {
                Some(x) => x,
                None => return Err(KernelError::InvalidArgument),
            };
            let file_end = match start.checked_add(ph.p_filesz as usize) {
                Some(x) => x,
                None => return Err(KernelError::InvalidArgument),
            };
            if file_end - start > image.len() {
                return Err(KernelError::InvalidArgument);
            }

            let mut prot = spec::UserPteFlags::empty();
            if ph.p_flags & PF_W != 0 {
                prot |= spec::UserPteFlags::WRITABLE;
            }
            if ph.p_flags & PF_X != 0 {
                prot |= spec::UserPteFlags::EXECUTABLE;
            }

            for i in (start..mem_end).step_by(spec::PAGE_SIZE) {
                spec::to_result(out.make_leaf(i as u64))?;
                spec::to_result(out.alloc_leaf(i as u64, prot))?;

                if i >= file_end {
                    continue;
                }

                let data = &image[(ph.p_offset as usize) + (i - start)..];

                let temp_base = temp_base.0.lock();

                spec::to_result(
                    out.fetch_page(i as u64, *temp_base, spec::UserPteFlags::WRITABLE)
                )?;
                
                let slice = core::slice::from_raw_parts_mut(
                    *temp_base as *mut u8,
                    spec::PAGE_SIZE,
                );
                let copy_end = if file_end - i < spec::PAGE_SIZE {
                    file_end - i
                } else {
                    spec::PAGE_SIZE
                };
                slice[..copy_end].copy_from_slice(&data[..copy_end]);
            }
        }
        Ok(ElfMetadata {
            entry_address: header.e_entry,
        })
    }
}

/// Builds a stack in the root page table `out`, starting from `start` and up to `start + size`.
pub fn build_stack(start: u64, size: u64, out: &spec::RootPageTable) -> Result<(), KernelError> {
    if start % (spec::PAGE_SIZE as u64) != 0 || size % (spec::PAGE_SIZE as u64) != 0 {
        return Err(KernelError::InvalidArgument);
    }

    let end = match start.checked_add(size) {
        Some(x) => x,
        None => return Err(KernelError::InvalidArgument),
    };

    for i in (start..end).step_by(spec::PAGE_SIZE) {
        unsafe {
            spec::to_result(out.make_leaf(i as u64))?;
            spec::to_result(out.alloc_leaf(i as u64, spec::UserPteFlags::WRITABLE))?;
        }
    }

    Ok(())
}

/// Builds and applies a stack to a task.
pub fn build_and_apply_stack(start: u64, size: u64, out: &spec::RootPageTable, task: &spec::BasicTask) -> Result<(), KernelError> {
    build_stack(start, size, out)?;

    unsafe {
        // Overflow already checked in `build_stack`.
        spec::to_result(task.set_register(SP_INDEX, start + size))?;
    }

    Ok(())
}