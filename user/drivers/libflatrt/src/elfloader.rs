use flatrt_elfloader::ElfTempMapBase;
use flatmk_sys::spec;
use crate::linux_mm::{LinuxMmState, Region};

#[no_mangle]
pub unsafe extern "C" fn libelfloader_load_and_apply(
    mm: &mut LinuxMmState,
    image_base: *const u8,
    image_len: usize,
    temp_base: u64,
    this_rpt: u64,
    task: u64,
    out_entry_address: &mut u64,
) -> i64 {
    let image = core::slice::from_raw_parts(image_base, image_len);
    let temp_base = ElfTempMapBase::new(temp_base);
    let this_rpt = spec::RootPageTable::new(spec::CPtr::new(this_rpt));
    let result = flatrt_elfloader::load(image, &temp_base, &this_rpt, (mm.shadow_base as usize..mm.shadow_limit as usize), |segment| {
        let region = Region {
            end: segment.base + segment.len,
            prot: segment.prot,
        };
        mm.regions.insert(segment.base, region);
        Ok(())
    });
    match result {
        Ok(md) => {
            match md.apply_to_task(&spec::BasicTask::new(spec::CPtr::new(task))) {
                Ok(()) => {
                    *out_entry_address = md.entry_address;
                    0
                },
                Err(e) => e as i64
            }
        }
        Err(e) => e as i64
    }
}

#[no_mangle]
pub unsafe extern "C" fn libelfloader_build_and_apply_stack(start: u64, size: usize, rpt: u64, task: u64) -> i64 {
    let rpt = spec::RootPageTable::new(spec::CPtr::new(rpt));
    let task = spec::BasicTask::new(spec::CPtr::new(task));
    match flatrt_elfloader::build_and_apply_stack(start, size as u64, &rpt, &task) {
        Ok(()) => 0,
        Err(e) => e as i64
    }
}