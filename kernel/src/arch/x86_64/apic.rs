//! Local APIC & IOAPIC-related code.
//! 
//! References:
//! 
//! - http://ethv.net/workshops/osdev/notes/notes-3

use x86::io::outb;
use crate::addr::*;
use core::arch::x86_64::__cpuid;

static mut LAPIC_BASE: *mut u32 = core::ptr::null_mut();
static mut IOAPIC_BASE: *mut u32 = core::ptr::null_mut();

unsafe fn lapic_read(index: usize) -> u32 {
    core::ptr::read_volatile(LAPIC_BASE.offset((index * 4) as isize))
}

unsafe fn lapic_write(index: usize, value: u32) {
    core::ptr::write_volatile(LAPIC_BASE.offset((index * 4) as isize), value);
}

unsafe fn ioapic_read(index: usize) -> u32 {
    core::ptr::write_volatile(IOAPIC_BASE.offset(0), index as u32);
    core::ptr::read_volatile(IOAPIC_BASE.offset(4))
}

unsafe fn ioapic_write(index: usize, value: u32) {
    core::ptr::write_volatile(IOAPIC_BASE.offset(0), index as u32);
    core::ptr::write_volatile(IOAPIC_BASE.offset(4), value);
}

pub(super) unsafe fn init_apic() {
    // The default LAPIC/IOAPIC base addresses.
    LAPIC_BASE = VirtAddr::from_phys(PhysAddr(0xfee00000u64)).as_mut_ptr();
    IOAPIC_BASE = VirtAddr::from_phys(PhysAddr(0xfec00000u64)).as_mut_ptr();

    // Disable PIC first.
    disable_pic();

    // Enable local APIC.
    let mut val = lapic_read(0xf);
    val |= 1 << 8;
    lapic_write(0xf, val);
    
    let apic_id = lapic_read(0x2);
    println!("Booting on processor with APIC ID: {}.", apic_id);

    // Keyboard IRQ.
    set_irq(1, 0, 33);

    // Timer.
    setup_timer();
}

/// Sets up and disables the PIC.
unsafe fn disable_pic() {
    /* Set ICW1 */
    outb(0x20, 0x11);
    outb(0xa0, 0x11);

    /* Set ICW2 (IRQ base offsets) */
    outb(0x21, 0xe0);
    outb(0xa1, 0xe8);

    /* Set ICW3 */
    outb(0x21, 4);
    outb(0xa1, 2);

    /* Set ICW4 */
    outb(0x21, 1);
    outb(0xa1, 1);

    /* Set OCW1 (interrupt masks) */
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
}

unsafe fn setup_timer() {
    const TIMER_IV: u32 = 32;
    const APIC_LVT_TIMER_MODE_PERIODIC: u32 = 0x20000;

    let mut freq = __cpuid(0x16).eax * 1000000;
    if freq == 0 {
        freq = __cpuid(0x40000000).eax;
    }
    println!("APIC timer frequency: {}.{:02} MHz", freq / 1000000, (freq / 10000) % 100);
    if freq == 0 {
        println!("Cannot get APIC timer frequency. Defaulting to 100MHz.");
        freq = 100000000;
    }

    // Set parameters and unmask interrupt.
    lapic_write(0x32, TIMER_IV | APIC_LVT_TIMER_MODE_PERIODIC);

    // Divide by 16.
    lapic_write(0x3e, 3);

    // Find the best initial counter value.
    // One tick per millisecond.
    let initial_count = freq / 16 / 1000 + 1;

    // Initial count.
    lapic_write(0x38, initial_count);
}

pub(super) unsafe fn check_and_send_eoi(index: u8) {
    let reg_index = (index >> 5) as usize;
    let bit_index = (index & 0b11111) as usize;
    if lapic_read(0x10 + reg_index) & (1u32 << bit_index) != 0 {
        lapic_write(0xb, 1);
    }
}

pub(super) unsafe fn set_irq(irq: u8, apic_id: u8, interrupt_vector: u8) {
    let low_index = 0x10 + (irq as usize) * 2;
    let high_index = low_index + 1;

    // Set APIC ID
    let mut high = ioapic_read(high_index);
    high &= !0xff000000u32;
    high |= (apic_id as u32) << 24;
    ioapic_write(high_index, high);

    let mut low = ioapic_read(low_index);
    low &= !(1u32 << 16); // Unmask IRQ
    low &= !(1u32 << 11); // Physical delivery mode
    low &= !0x700u32; // Fixed delivery mode
    low &= !0xffu32; // Delivery vector
    low |= interrupt_vector as u32;
    ioapic_write(low_index, low);
}
