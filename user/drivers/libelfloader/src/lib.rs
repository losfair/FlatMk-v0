#![no_std]
#![feature(asm)]

use flatrt_elfloader::ElfTempMapBase;
use flatmk_sys::spec;

#[no_mangle]
pub unsafe extern "C" fn libelfloader_load_and_apply(image_base: *const u8, image_len: usize, temp_base: u64, rpt: u64, task: u64, out_entry_address: &mut u64) -> i64 {
    let image = core::slice::from_raw_parts(image_base, image_len);
    let temp_base = ElfTempMapBase::new(temp_base);
    let rpt = spec::RootPageTable::new(spec::CPtr::new(rpt));
    let result = flatrt_elfloader::load(image, &temp_base, &rpt);
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

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        asm!("ud2" :::: "volatile");
    }
    loop {}
}