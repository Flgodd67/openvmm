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
    ) -> Result<bool, Error> {
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

        Ok(set)
    }

    fn must_flush_regs_on(_runner: &ProcessorRunner<'a, Self>, _name: HvRegisterName) -> bool {
        false
    }

    fn try_get_reg(
        runner: &ProcessorRunner<'a, Self>,
        _vtl: GuestVtl,
        name: HvRegisterName,
    ) -> Result<Option<HvRegisterValue>, Error> {
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
        Ok(value)
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

