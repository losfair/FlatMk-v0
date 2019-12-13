use goblin::elf::{
    header::header64::Header, program_header::program_header64::ProgramHeader, program_header::*,
};

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

pub fn load(image: &[u8], out: &mut [u8], out_base: u64) -> Option<u64> {
    let header: Header = unsafe {
        if let Some(x) = image.read_raw() {
            x
        } else {
            return None;
        }
    };
    if header.e_phoff >= image.len() as u64 {
        return None;
    }

    let mut segments = &image[header.e_phoff as usize..];
    for _ in 0..header.e_phnum {
        let ph: ProgramHeader = unsafe {
            if let Some(x) = segments.read_raw() {
                x
            } else {
                return None;
            }
        };
        segments = &segments[core::mem::size_of::<ProgramHeader>()..];
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_vaddr < out_base {
            continue;
        }
        if ph.p_vaddr - out_base > out.len() as u64 {
            continue;
        }
        // TODO: check size
        let data = &image[ph.p_offset as usize..];
        if data.len() < ph.p_filesz as usize {
            return None;
        }
        let data = &data[..ph.p_filesz as usize];
        out[(ph.p_vaddr - out_base) as usize..(ph.p_vaddr - out_base + ph.p_filesz) as usize]
            .copy_from_slice(data);
    }
    Some(header.e_entry)
}
