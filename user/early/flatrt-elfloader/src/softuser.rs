use flatmk_sys::spec::{self, KernelError};
use goblin::elf::{
    header::header32::Header, program_header::program_header32::ProgramHeader, program_header::*,
};
use spin::Mutex;
use core::ops::Range;
use crate::{ElfTempMapBase, ReadRaw};

/// Segment is writable.
const PF_W: u32 = 1 << 1;

/// ELF image metadata.
#[derive(Clone, Debug)]
pub struct ElfMetadata {
    /// The entry virtual address.
    pub entry_address: u32,
}

/// Loads an image into `out`.
/// 
/// The leaf entry of `temp_base` must first be built.
pub fn load(image: &[u8], temp_base: &ElfTempMapBase, out: &spec::RootPageTable, va_space: Range<usize>) -> Result<ElfMetadata, KernelError> {
    unsafe {
        let header: Header = match image.read_raw() {
            Some(x) => x,
            None => return Err(KernelError::InvalidArgument),
        };
        if header.e_phoff >= image.len() as u32 {
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
            let mut padding_before: usize = 0;
            let start = ph.p_vaddr as usize;
            if start % spec::PAGE_SIZE != 0 {
                padding_before = start % spec::PAGE_SIZE;
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

            for i in (start - padding_before..mem_end).step_by(spec::PAGE_SIZE) {
                // VA offsets & check.
                let va_begin = match i.checked_add(va_space.start) {
                    Some(x) => x as u64,
                    None => return Err(KernelError::InvalidAddress),
                };
                let va_end = match va_begin.checked_add(spec::PAGE_SIZE as u64) {
                    Some(x) => x,
                    None => return Err(KernelError::InvalidAddress),
                };
                if va_end > va_space.end as u64 {
                    return Err(KernelError::InvalidAddress);
                }

                spec::to_result(out.alloc_leaf(va_begin, prot))?;

                if i >= file_end {
                    continue;
                }

                let temp_base = temp_base.0.lock();

                spec::to_result(
                    out.fetch_page(va_begin, *temp_base, spec::UserPteFlags::WRITABLE)
                )?;
                
                let slice = core::slice::from_raw_parts_mut(
                    *temp_base as *mut u8,
                    spec::PAGE_SIZE,
                );

                if i < start {
                    // Handle padding.
                    let data = &image[ph.p_offset as usize..];
                    slice[padding_before..spec::PAGE_SIZE].copy_from_slice(&data[..spec::PAGE_SIZE - padding_before]);
                } else {
                    let copy_end = if file_end - i < spec::PAGE_SIZE {
                        file_end - i
                    } else {
                        spec::PAGE_SIZE
                    };
                    let data = &image[(ph.p_offset as usize) + (i - start)..];
                    slice[..copy_end].copy_from_slice(&data[..copy_end]);
                }
            }
        }
        Ok(ElfMetadata {
            entry_address: header.e_entry,
        })
    }
}
