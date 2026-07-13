// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! aarch64 specific tests.

#![cfg(target_arch = "aarch64")]
#![allow(
    unsafe_code,
    reason = "global_asm! required for AArch64 trampoline code"
)]

use crate::prelude::*;
use tmk_protocol as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::Relaxed;
use tmk_core::TestContext;
use tmk_core::aarch64::IrqContext;
use tmk_core::aarch64::disable_virtual_timer;
use tmk_core::aarch64::read_cntfrq;
use tmk_core::aarch64::read_cntvct;
use tmk_core::aarch64::set_virtual_timer_compare;
use tmk_core::aarch64;

#[tmk_test]
fn virtual_timer_irq(t: TestContext<'_>) {
    let timer_fired = AtomicBool::new(false);
    let timer_isr = |ctx: &mut aarch64::IrqContext| {
        if ctx.intid == aarch64::VIRTUAL_TIMER_PPI {
            aarch64::disable_virtual_timer();
            timer_fired.store(true, Relaxed);
        }
    };

    t.scope.subscope(|s| {
        s.set_irq_handler(&timer_isr);
        s.enable_gic_irq(aarch64::VIRTUAL_TIMER_PPI);

        let frequency = aarch64::read_cntfrq();
        let start = aarch64::read_cntvct();
        let ticks_until_interrupt = core::cmp::max(frequency / 100, 1);
        let timeout_ticks = core::cmp::max(frequency, ticks_until_interrupt * 10);

        aarch64::set_virtual_timer_compare(start + ticks_until_interrupt);
        s.enable_interrupts();

        while !timer_fired.load(Relaxed)
            && aarch64::read_cntvct().wrapping_sub(start) < timeout_ticks
        {
            aarch64::poll_interrupts();
            core::hint::spin_loop();
        }

        s.disable_interrupts();
        aarch64::disable_virtual_timer();
        s.disable_gic_irq(aarch64::VIRTUAL_TIMER_PPI);
    });

    assert!(
        timer_fired.load(Relaxed),
        "virtual timer interrupt did not fire"
    );
}

// #[tmk_test]
// fn gic_virtual_timer(t: TestContext<'_>) {
//     // Use the INTID your plane1 virtual platform wires the timer to.
//     //
//     // You mentioned PPI 20, so use 20 if that is what the vGIC exposes.
//     // For the architectural virtual timer on many GIC systems, this is often INTID 27.
//     const TIMER_INTID: u32 = 20;

//     let timer_fired = AtomicBool::new(false);

//     let timer_isr = |ctx: &mut IrqContext| {
//         log!("timer fired, intid={}", ctx.intid);

//         assert_eq!(
//             ctx.intid, TIMER_INTID,
//             "unexpected interrupt ID"
//         );

//         timer_fired.store(true, Relaxed);
//     };

//     t.scope.subscope(|s| {
//         // Install the plane1 IRQ callback.
//         s.set_irq_handler(&timer_isr);

//         log!("before enable_gic_for_current_vp called");
//         // Enable this PPI in the vGIC Redistributor for this VP.
//         s.enable_gic_irq(TIMER_INTID);

//         // Program the virtual timer.
//         let freq = read_cntfrq();
//         let start = read_cntvct();

//         // Fire after about 10 ms.
//         let delay_ticks = freq / 100;
//         let compare = start + delay_ticks;

//         set_virtual_timer_compare(compare);

//         // Now allow IRQ exceptions to be taken.
//         s.enable_interrupts();

//         for _ in 0..1_000_000_000 {
//             if timer_fired.load(Relaxed) {
//                 break;
//             }

//             core::hint::spin_loop();
//         }

//         assert!(
//             timer_fired.load(Relaxed),
//             "virtual timer interrupt did not fire"
//         );

//         let now = read_cntvct();
//         log!("start={}, compare={}, now={}", start, compare, now);

//         assert!(
//             now >= compare,
//             "timer fired before the compare value"
//         );

//         disable_virtual_timer();
//         s.disable_gic_irq(TIMER_INTID);
//     });
// }

core::arch::global_asm! {
    ".global instruction_abort_outside_par_entry",
    "instruction_abort_outside_par_entry:",
    "movz x16, #0x0000",
    "movk x16, #0x0000, lsl #16",
    "movk x16, #0xffff, lsl #32",
    "movk x16, #0x0000, lsl #48",
    "br x16",
}

unsafe extern "C" {
    fn instruction_abort_outside_par_entry() -> !;
}

#[tmk_test(expected_failure, linux_only)]
fn instruction_abort_outside_par(_: TestContext<'_>) {
    log!("instruction_abort_outside_par");

    // SAFETY: This test intentionally jumps to an assembly entry point that
    // triggers an instruction abort. The symbol is defined in this module via
    // `global_asm!` and is declared `-> !`, so it is not expected to return.
    unsafe {
        instruction_abort_outside_par_entry();
    }
}

core::arch::global_asm! {
    ".global instruction_abort_ripas_empty_entry",
    "instruction_abort_ripas_empty_entry:",
    "movz x16, #0x0000",
    "br x16",
}

unsafe extern "C" {
    fn instruction_abort_ripas_empty_entry() -> !;
}

#[tmk_test(expected_failure, linux_only)]
fn instruction_abort_ripas_empty(_: TestContext<'_>) {
    log!("instruction_abort_ripas_empty");

    // SAFETY: This test intentionally transfers control to an assembly entry
    // point that executes from an address chosen to provoke the expected
    // instruction abort. The entry point is defined above and never returns.
    unsafe {
        instruction_abort_ripas_empty_entry();
    }
}

core::arch::global_asm! {
    ".global instruction_abort_permissions_enabled_entry",
    "instruction_abort_permissions_enabled_entry:",
    "movz x16, #0xf000",
    "movk x16, #0x847f, lsl #16",
    "br x16",
}

unsafe extern "C" {
    fn instruction_abort_permissions_enabled_entry() -> !;
}

#[tmk_test(expected_failure, linux_only)]
fn instruction_abort_permissions_enabled(_: TestContext<'_>) {
    log!("instruction_abort_permissions_enabled");

    // SAFETY: This test intentionally calls an assembly entry point that jumps
    // to an address expected to fault under the configured permissions. The
    // entry point is defined in this module and is declared `-> !`.
    unsafe {
        instruction_abort_permissions_enabled_entry();
    }
}
