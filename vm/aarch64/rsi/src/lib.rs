// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Arm CCA specific definitions, including for the Realm Service Interface (RSI).
#![allow(unsafe_code)]

// TODO: CCA: A lot of the code in this module depends on who gets to package the RSI calls.
// If OpenVMM is the one that packages the RSI calls, then this module should be
// responsible for defining the RSI calls and their parameters. If the kernel driver is the one
// that packages the RSI calls, then this module should only define the data structures used
// to communicate with the kernel driver, and the RSI calls should be defined in the kernel driver.

/// CCA memory permission index, used to set and get Stage 2 memory access permissions
/// via the RSI interface.
#[allow(missing_docs)]
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CcaMemPermIndex {
    Index0,
    Index1,
    Index2,
    Index3,
    Index4,
    Index5,
    Index6,
    Index7,
    Index8,
    Index9,
    Index10,
    Index11,
    Index12,
    Index13,
    #[default]
    Index14,
}

/// Read the CNTFRQ_EL0 system register, which contains the frequency of the
/// system timer in Hz. This is used to determine the frequency of the
/// system timer for the current execution level (EL0).
#[inline]
pub fn read_cntfrq_el0() -> u64 {
    let freq: u64;
    // SAFETY: no safety requirements, just reading an EL0 sysreg
    unsafe {
        core::arch::asm!(
            "mrs {cntfrq}, cntfrq_el0",
            cntfrq = out(reg) freq,
            options(nomem, nostack, preserves_flags)
        );
    };
    freq
}