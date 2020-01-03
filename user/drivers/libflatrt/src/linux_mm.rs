use alloc::collections::btree_map::BTreeMap;
use flatmk_sys::spec;
use alloc::boxed::Box;
use core::mem::MaybeUninit;

pub struct LinuxMmState {
    pub managed: spec::BasicTask,
    pub regions: BTreeMap<u64, Region>,
    pub shadow_base: u64,
    pub shadow_limit: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Region {
    pub end: u64,
    pub prot: spec::UserPteFlags,
}

#[no_mangle]
pub unsafe extern "C" fn linux_mm_new(
    managed: spec::CPtr,
    shadow_base: u64,
    shadow_limit: u64,
) -> *mut LinuxMmState {
    Box::into_raw(Box::new(LinuxMmState {
        managed: spec::BasicTask::new(managed),
        regions: BTreeMap::new(),
        shadow_base: shadow_base,
        shadow_limit: shadow_limit,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn linux_mm_validate_target_va(mm: &LinuxMmState, va: u64, out_prot: &mut MaybeUninit<spec::UserPteFlags>) -> i32 {
    match mm.regions.range(0..=va).last() {
        Some(x) if x.1.end > va => {
            out_prot.write(x.1.prot);
            1
        }
        _ => {
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn linux_mm_insert_region(mm: &mut LinuxMmState, start: u64, end: u64, prot: u64) -> i64 {
    let prot = match spec::UserPteFlags::from_bits(prot) {
        Some(x) => x,
        None => return spec::KernelError::InvalidArgument as i64,
    };
    mm.regions.insert(start, Region {
        end,
        prot,
    });
    0
}
