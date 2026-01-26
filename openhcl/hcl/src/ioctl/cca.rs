//! Backing for CCA partitions.

use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

use super::Hcl;
use super::HclVp;
use super::MshvVtl;
use super::NoRunner;
use super::ProcessorRunner;
use crate::GuestVtl;
use crate::ioctl::Error;
use crate::ioctl::ioctls::mshv_realm_config;
use crate::ioctl::ioctls::mshv_rsi_set_mem_perm;
use crate::ioctl::ioctls::mshv_rsi_sysreg_write;
use crate::ioctl::ioctls::{hcl_realm_config, hcl_rsi_set_mem_perm, hcl_rsi_sysreg_write};
use crate::protocol::RSI_PLANE_ENTER_FLAGS_TRAP_SIMD;
use crate::protocol::RSI_PLANE_GIC_NUM_LRS;
use crate::protocol::RSI_PLANE_NR_GPRS;
use crate::protocol::cca_rsi_plane_entry;
use crate::protocol::cca_rsi_plane_exit;
use crate::protocol::cca_rsi_plane_run;
use aarch64defs::SystemReg;
use hvdef::HvArm64RegisterName;
use hvdef::HvRegisterName;
use hvdef::HvRegisterValue;
// use rsi::{RsiCall, RsiInput, RsiOutput, RsiReturnCode};
use sidecar_client::SidecarVp;

use crate::mapped_page::MappedPage;
use std::fs::OpenOptions;
use std::io;


/// Runner backing for CCA partitions.
pub struct Cca {
    plane_run: MappedPage<cca_rsi_plane_run>,
}

impl Cca {
    /// Create new CCA runner backing.
    pub fn new() -> Self {
        // SAFETY: MappedPage is safe to create, it will allocate a page and
        // ensure the pointer is valid for the lifetime of the struct.
        let plane_run = Self::allocate_plane_run_page().expect("Failed to allocate page");
        Self { plane_run }
    }

    /// Allocate a new page for the CCA plane_run struct.
    pub(crate) fn allocate_plane_run_page() -> io::Result<MappedPage<cca_rsi_plane_run>> {
        // Open a file that can be mmap'ed. /dev/zero is a common choice.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/zero")?;
        // Allocate a page. MappedPage ensures the page is fixed, and its lifetime
        // controls when the mapping is unmapped.
        MappedPage::new(&file, 0)
    }
}

impl ProcessorRunner<'_, Cca> {
    /// Returns a reference to the current VTL's CPU context.
    pub fn cpu_context(&self) -> &u64 {
        // SAFETY: the cpu context will not be concurrently accessed by the
        // hypervisor while this VP is in VTL2.
        unsafe { &*(&raw mut (*self.run.get()).context).cast() }
    }

    /// Returns a mutable reference to the current VTL's CPU context.
    pub fn cpu_context_mut(&mut self) -> &mut u64 {
        // SAFETY: the cpu context will not be concurrently accessed by the
        // hypervisor while this VP is in VTL2.
        unsafe { &mut *(&raw mut (*self.run.get()).context).cast() }
    }

    /// Returns a mutable reference to the current VTL's CCA RSI plane run structure.
    pub fn cca_rsi_plane_run_mut(&mut self) -> &mut cca_rsi_plane_run {
        // SAFETY: The plane_run page is valid and mapped for the lifetime of the struct.
        self.state.plane_run.as_mut().get_mut()
    }

    /// Returns a mutable reference to the current VTL's plane entry structure.
    pub fn cca_rsi_plane_entry(&mut self) -> &mut cca_rsi_plane_entry {
        &mut self.state.plane_run.as_mut().get_mut().entry
    }

    /// Returns a mutable reference to the current VTL's plane exit structure.
    pub fn cca_rsi_plane_exit(&self) -> &cca_rsi_plane_exit {
        // SAFETY: The plane_run page is valid and mapped for the lifetime of the struct.
        &(unsafe { &*self.state.plane_run.as_ref().get() }).exit
    }

    /// Set the value of the plane entry flags.
    pub fn cca_set_entry_flags(&mut self, value: u64) {
        self.cca_rsi_plane_entry().flags = value;
    }

    /// Set the value of the plane entry PC.
    pub fn cca_set_entry_pc(&mut self, value: u64) {
        self.cca_rsi_plane_entry().pc = value;
    }

    /// Set the value of the plane entry GPRs.
    pub fn cca_set_entry_gprs(&mut self, values: [u64; RSI_PLANE_NR_GPRS]) {
        self.cca_rsi_plane_entry().gprs = values;
    }

    /// Set the value of the plane entry gicv3_hcr register.
    pub fn cca_set_entry_gicv3_hcr(&mut self, value: u64) {
        self.cca_rsi_plane_entry().gicv3_hcr = value;
    }

    /// Set the value of the plane entry GIC v3 LRs.
    pub fn cca_set_entry_gicv3_lrs(&mut self, values: [u64; RSI_PLANE_GIC_NUM_LRS]) {
        self.cca_rsi_plane_entry().gicv3_lrs = values;
    }

    /// Set the value of a single plane entry GPR.
    fn cca_set_entry_gpr(&mut self, register: usize, value: u64) {
        assert!(register < RSI_PLANE_NR_GPRS);
        self.cca_rsi_plane_entry().gprs[register] = value;
    }

    /// Get the value of a single plane entry GPR.
    fn cca_get_entry_gpr(&self, register: usize) -> u64 {
        assert!(register < RSI_PLANE_NR_GPRS);
        self.cca_rsi_plane_exit().gprs[register]
    }

    /// Flush the given value for a system register to the RMM.
    pub fn cca_sysreg_write(
        &mut self,
        vtl: GuestVtl,
        name: SystemReg,
        value: u64,
    ) -> Result<(), Error> {
        self.hcl
            .rsi_sysreg_write(vtl, u32::from(name.0) as u64, value)
            .map_err(Error::SetRegisters)
    }

    /// Update the address of the `plane_run` structure in `mshv_vtl_run.context`.
    pub fn cca_set_plane_enter(&mut self) {
        // SAFETY: The plane_run page is valid and mapped for the lifetime of the struct.
        let plane_run: &mut u64 = unsafe { &mut *(&raw mut (*self.run.get()).context).cast() };
        let plane_run_phys = virt_to_phys(self.state.plane_run.as_ptr() as u64)
            .expect("Failed to get plane_run physical address");
        *plane_run = plane_run_phys;
    }

    /// Set flag to enable trapping of SIMD operations in the lower VTL.
    pub fn cca_plane_trap_simd(&mut self) {
        let plane_run: &mut cca_rsi_plane_run = self.state.plane_run.as_mut().get_mut();
        plane_run.entry.flags |= RSI_PLANE_ENTER_FLAGS_TRAP_SIMD;
    }

    /// Unset flag that enables trapping of SIMD operations in lower VTL
    /// (i.e., SIMD operations are not trapped).
    pub fn cca_plane_no_trap_simd(&mut self) {
        // SAFETY: The plane_run page is valid and mapped for the lifetime of the struct.
        let plane_run: &mut cca_rsi_plane_run = self.state.plane_run.as_mut().get_mut();
        plane_run.entry.flags &= !RSI_PLANE_ENTER_FLAGS_TRAP_SIMD;
    }

    /// Set the default value for PSTATE for the lower VTL.
    pub fn cca_set_default_pstate(&mut self) {
        // SPSR_EL2_MODE_EL1h | SPSR_EL2_nRW_AARCH64 | SPSR_EL2_F_BIT | SPSR_EL2_I_BIT | SPSR_EL2_A_BIT | SPSR_EL2_D_BIT
        self.cca_rsi_plane_entry().pstate = 0x3c5;
    }

    // pub fn read_translation_registers(&self) -> TranslationRegisters {
    //     let cpsr = rsi_plane_sysreg_read()
    //     TranslationRegisters {
    //         cpsr: cpsr.into(),
    //         sctlr: sctlr.into(),
    //         tcr: tcr.into(),
    //         ttbr0,
    //         ttbr1,
    //         syndrome,
    //         encryption_mode: virt_support_aarch64emu::translate::EncryptionMode::None,
    //     }
    // }
}

// CCA: NOTE this implementation is lifted from the aarch64 VBS implementation
// and might need more work to make it CCA-aligned.
impl<'a> super::BackingPrivate<'a> for Cca {
    fn new(vp: &HclVp, sidecar: Option<&SidecarVp<'_>>, _hcl: &Hcl) -> Result<Self, NoRunner> {
        assert!(sidecar.is_none());
        let super::BackingState::Cca = &vp.backing else {
            unreachable!()
        };
        let cca = Cca::new();

        Ok(cca)
    }

    fn try_set_reg(
        runner: &mut ProcessorRunner<'a, Self>,
        _vtl: GuestVtl,
        name: HvRegisterName,
        value: HvRegisterValue,
    ) -> bool {
        // Try to set the register in the CPU context, the fastest path. Only
        // VTL-shared registers can be set this way: the CPU context only
        // exposes the last VTL, and if we entered VTL2 on an interrupt,
        // OpenHCL doesn't know what the last VTL is.
        // NOTE: for VBS x18 is omitted here as it is managed by the hypervisor,
        //       do we need to do the same here?
        let set = match name.into() {
            HvArm64RegisterName::X0
            | HvArm64RegisterName::X1
            | HvArm64RegisterName::X2
            | HvArm64RegisterName::X3
            | HvArm64RegisterName::X4
            | HvArm64RegisterName::X5
            | HvArm64RegisterName::X6
            | HvArm64RegisterName::X7
            | HvArm64RegisterName::X8
            | HvArm64RegisterName::X9
            | HvArm64RegisterName::X10
            | HvArm64RegisterName::X11
            | HvArm64RegisterName::X12
            | HvArm64RegisterName::X13
            | HvArm64RegisterName::X14
            | HvArm64RegisterName::X15
            | HvArm64RegisterName::X16
            | HvArm64RegisterName::X17
            | HvArm64RegisterName::X18
            | HvArm64RegisterName::X19
            | HvArm64RegisterName::X20
            | HvArm64RegisterName::X21
            | HvArm64RegisterName::X22
            | HvArm64RegisterName::X23
            | HvArm64RegisterName::X24
            | HvArm64RegisterName::X25
            | HvArm64RegisterName::X26
            | HvArm64RegisterName::X27
            | HvArm64RegisterName::X28
            | HvArm64RegisterName::XFp
            | HvArm64RegisterName::XLr => {
                runner.cca_set_entry_gpr(
                    (name.0 - HvArm64RegisterName::X0.0) as usize,
                    value.as_u64(),
                );
                true
            }
            _ => false,
        };

        set
    }

    fn must_flush_regs_on(_runner: &ProcessorRunner<'a, Self>, _name: HvRegisterName) -> bool {
        false
    }

    fn try_get_reg(
        runner: &ProcessorRunner<'a, Self>,
        _vtl: GuestVtl,
        name: HvRegisterName,
    ) -> Option<HvRegisterValue> {
        // Try to get the register from the CPU context, the fastest path.
        // NOTE: for VBS x18 is omitted here as it is managed by the hypervisor,
        //       do we need to do the same here?
        let value = match name.into() {
            HvArm64RegisterName::X0
            | HvArm64RegisterName::X1
            | HvArm64RegisterName::X2
            | HvArm64RegisterName::X3
            | HvArm64RegisterName::X4
            | HvArm64RegisterName::X5
            | HvArm64RegisterName::X6
            | HvArm64RegisterName::X7
            | HvArm64RegisterName::X8
            | HvArm64RegisterName::X9
            | HvArm64RegisterName::X10
            | HvArm64RegisterName::X11
            | HvArm64RegisterName::X12
            | HvArm64RegisterName::X13
            | HvArm64RegisterName::X14
            | HvArm64RegisterName::X15
            | HvArm64RegisterName::X16
            | HvArm64RegisterName::X17
            | HvArm64RegisterName::X18
            | HvArm64RegisterName::X19
            | HvArm64RegisterName::X20
            | HvArm64RegisterName::X21
            | HvArm64RegisterName::X22
            | HvArm64RegisterName::X23
            | HvArm64RegisterName::X24
            | HvArm64RegisterName::X25
            | HvArm64RegisterName::X26
            | HvArm64RegisterName::X27
            | HvArm64RegisterName::X28
            | HvArm64RegisterName::XFp
            | HvArm64RegisterName::XLr => Some(
                runner
                    .cca_get_entry_gpr((name.0 - HvArm64RegisterName::X0.0) as usize)
                    .into(),
            ),
            _ => None,
        };
        value
    }

    fn flush_register_page(_runner: &mut ProcessorRunner<'a, Self>) {}
}

/// Representation of the Realm config data available to Plane 0.
///
/// * ipa_width is the size of the realm protected memory space
/// * hash_algo is the hash alg used for measurements
/// * num_aux_planes indicates how many low-privilege planes exist
/// * gicv3_vtr shows part of the GICv3 configuration for the
///     realm (needed for GIC virtualisation)
// TODO: CCA: make this Rust-native
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct RsiRealmConfig {
    ipa_width: u64,
    hash_algo: u64,
    num_aux_planes: u64,
    gicv3_vtr: u64,
}

impl RsiRealmConfig {
    /// Get the IPA width of the realm
    pub fn ipa_width(&self) -> u64 {
        self.ipa_width
    }
}

impl From<mshv_realm_config> for RsiRealmConfig {
    fn from(value: mshv_realm_config) -> Self {
        RsiRealmConfig {
            ipa_width: value.ipa_width,
            hash_algo: value.algorithm,
            num_aux_planes: value.num_aux_planes,
            gicv3_vtr: value.gicv3_vtr,
        }
    }
}

impl MshvVtl {
    /// Get the realm-specific parameters from the RMM
    pub fn get_realm_config(&self) -> Result<RsiRealmConfig, Error> {
        let mut config = mshv_realm_config::default();

        // SAFETY: Calling hcl_realm_config ioctl with the correct arguments.
        unsafe {
            hcl_realm_config(self.file.as_raw_fd(), &mut config)
                .map_err(|_| Error::InvalidRegisterValue)?;
        }

        Ok(config.into())
    }

    /// Write the value of a system register for the given VTL
    pub fn rsi_sysreg_write(
        &self,
        vtl: GuestVtl,
        sysreg: u64,
        value: u64,
    ) -> Result<(), hvdef::HvError> {
        let mut sysreg_write = mshv_rsi_sysreg_write::default();
        sysreg_write.vtl = vtl.into();
        sysreg_write.sysreg = sysreg;
        sysreg_write.value = value;

        // SAFETY: Calling hcl_rsi_sysreg_write ioctl with the correct arguments.
        unsafe {
            hcl_rsi_sysreg_write(self.file.as_raw_fd(), &sysreg_write)
                .map_err(|_| hvdef::HvError::InvalidRegisterValue)?;
        }
        Ok(())
    }

    /// Assign given memory range to the VTL.
    pub fn rsi_set_mem_perm(
        &self,
        vtl: GuestVtl,
        base_addr: u64,
        top_addr: u64,
    ) -> Result<(), hvdef::HvError> {
        let set_mem_perm = mshv_rsi_set_mem_perm {
            plane: if vtl == GuestVtl::Vtl0 {
                1
            } else {
                panic!("Invalid VTL")
            },
            base_addr,
            top_addr,
        };

        // SAFETY: Calling hcl_rsi_set_mem_perm ioctl with the correct arguments.
        unsafe {
            hcl_rsi_set_mem_perm(self.file.as_raw_fd(), &set_mem_perm)
                .map_err(|_| hvdef::HvError::InvalidRegisterValue)?;
        }
        Ok(())
    }
}

