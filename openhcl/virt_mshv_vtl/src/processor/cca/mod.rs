
//! Processor support for CCA Planes.

use std::sync::atomic::AtomicU8;

use super::HardwareIsolatedBacking;
use super::vp_state;
use crate::TlbFlushLockAccess;
use crate::UhPartitionInner;
// use crate::processor::UhRunVpError;
use crate::{BackingShared, UhCvmPartitionState,/* UhCvmVpState,*/ UhPartitionNewParams};
use aarch64defs::EsrEl2;
use aarch64defs::SystemReg;
use hcl::protocol::cca_rsi_plane_exit;
use hcl::{GuestVtl, ioctl::cca::Cca};
use hv1_emulator::hv::ProcessorVtlHv;
use hv1_emulator::synic::ProcessorSynic;
use hv1_structs::VtlArray;
use inspect::{Inspect, InspectMut};
use virt::VpIndex;
use virt::aarch64::vp;
use virt::io::CpuIo;
use virt::{VpHaltReason, aarch64::vp::AccessVpState};
use virt_support_aarch64emu::translate::TranslationRegisters;

use super::{BackingSharedParams, UhProcessor, private::BackingPrivate, vp_state::UhVpStateAccess};

#[derive(InspectMut)]
pub struct CcaBacked {
    vtls: VtlArray<CcaVtl, 2>,

    cvm: UhCvmVpState
}

#[derive(InspectMut)]
struct CcaVtl {
    sp_el0: u64,
    sp_el1: u64,
    cpsr: u64,
}

#[derive(Inspect)]
pub struct CcaBackedShared {
    pub(crate) cvm: UhCvmPartitionState,
    // CCA: potentially needed:
    // The synic state used for untrusted SINTs, that is, the SINTs for which
    // the guest thinks it is interacting directly with the untrusted
    // hypervisor via an architecture-specific interface.
    #[inspect(iter_by_index)]
    active_vtl: Vec<AtomicU8>,
}

impl CcaBackedShared {
    pub(crate) fn new(
        partition_params: &UhPartitionNewParams<'_>,
        params: BackingSharedParams,
    ) -> Result<Self, crate::Error> {
        Ok(Self {
            cvm: params.cvm_state.unwrap(),
            // VPs start in VTL 2.
            active_vtl: std::iter::repeat_n(2, partition_params.topology.vp_count() as usize)
                .map(AtomicU8::new)
                .collect(),
        })
    }
}

#[derive(Default)]
pub struct CcaEmulationCache {
    segs: [Option<SegmentRegister>; 6],
    cr0: Option<u64>,
}

#[expect(private_interfaces)]
impl BackingPrivate for CcaBacked {
    type HclBacking<'cca> = Cca;
    type Shared = CcaBackedShared;
    type EmulationCache = CcaEmulationCache;

    fn shared(shared: &BackingShared) -> &Self::Shared {
        let BackingShared::Cca(shared) = shared else {
            unreachable!()
        };
        shared
    }

    fn new(
        params: super::BackingParams<'_, '_, Self>,
        shared: &Shared,
    ) -> Result<Self, crate::Error> {
        // TODO: CCA: see below
        // TODO TDX: ssp is for shadow stack
        // TODO TDX: direct overlay like snp?

        // TODO: CCA: do we need a "flush_page" here (?)
        // TODO: CCA: initialize untrusted synic (?)

        Ok(Self {
            vtls: VtlArray::new(CcaVtl::new()),
            cvm: UhCvmVpState::new(
                &shared.cvm,
                params.partition,
                params.vp_info,
                UhDirectOverlay::Count as usize,
            )?,
        })
    }

    type StateAccess<'p, 'a>
        = UhVpStateAccess<'a, 'p, Self>
    where
        Self: 'a + 'p,
        'p: 'a;

    fn access_vp_state<'a, 'p>(
        this: &'a mut UhProcessor<'p, Self>,
        vtl: GuestVtl,
    ) -> Self::StateAccess<'p, 'a> {
        UhVpStateAccess::new(this, vtl)
    }

    fn init(_this: &mut UhProcessor<'_, Self>) {
        // TODO: CCA: init non-zero registers for plane?
        // TODO: CCA: SIMD regs?
    }

    async fn run_vp(
        this: &mut UhProcessor<'_, Self>,
        dev: &impl CpuIo,
        _stop: &mut virt::StopVp<'_>,
    ) -> Result<(), VpHaltReason<UhRunVpError>> {
        // TODO: CCA: TDX implementation handled "deliverability notifications" here,
        // no clue what they're about, potentially some VBS stuff?

        // TODO: CCA: NEXT: move this to `init`?
        this.set_plane_enter();

        // Run the CCA plane.
        // This will return when the plane exits.
        let intercepted = this
            .runner
            .run()
            .map_err(|e| VpHaltReason::Hypervisor(UhRunVpError::Run(e)))?;

        // Preserve the plane context, so we can restore it later.
        this.preserve_plane_context();

        if intercepted {
            // CCA: note, this is a very simplified version of the exit handling,
            // just enough to get the TMK running.
            // TODO: CCA: NEXT: document how we integrate with the wider emulation
            // system.
            let cca_exit = CcaExit(this.runner.cca_rsi_plane_exit());
            let exit_reason = cca_exit.exit_reason();
            let esr_el2 = cca_exit.esr_el2();
            match exit_reason {
                PlaneExitReason::Sync => {
                    match cca_exit.esr_el2_class() {
                        ExceptionClass::DataAbort => {
                            // get the address that caused the data abort
                            let address = cca_exit.far_el2();
                            // Based on the CpuIo impl in tmk_vmm/src/run.rs, dev.is_mmio(address)
                            // always returns false, so we handle MMIO access here.

                            if esr_el2.is_write() {
                                // Handle MMIO write
                                dev.write_mmio(
                                    this.vp_index(),
                                    address,
                                    &this.runner.cca_rsi_plane_exit().gprs[esr_el2.srt() as usize]
                                        .to_ne_bytes(),
                                )
                                .await;
                            } else {
                                // Handle MMIO read
                                todo!();
                            }
                            this.runner.cca_rsi_plane_entry().pc += 4; // Advance PC
                        }
                        ExceptionClass::InstructionAbort => {
                            // Handle instruction abort
                            todo!();
                        }
                        ExceptionClass::SimdAccess => {
                            this.runner.cca_plane_no_trap_simd();
                        }
                    }
                }
                PlaneExitReason::Irq => {
                    // Handle IRQ exit
                    todo!();
                }
            }
        }
        Ok(())
    }

    fn poll_apic(
        _this: &mut UhProcessor<'_, Self>,
        _vtl: GuestVtl,
        _scan_irr: bool,
    ) -> Result<(), UhRunVpError> {
        // TODO: CCA: poll GIC?
        Ok(())
    }

    fn request_extint_readiness(_this: &mut UhProcessor<'_, Self>) {
        unreachable!("extint managed through software apic")
    }

    fn request_untrusted_sint_readiness(_this: &mut UhProcessor<'_, Self>, _sints: u16) {
        // TODO: CCA: handle this for CCA untrusted synic
        unimplemented!();
    }

    fn handle_cross_vtl_interrupts(
        _this: &mut UhProcessor<'_, Self>,
        _dev: &impl CpuIo,
    ) -> Result<bool, UhRunVpError> {
        // TODO: CCA: handle cross VTL interrupts when GIC support is added
        Ok(false)
    }

    fn hv(&self, _vtl: GuestVtl) -> Option<&ProcessorVtlHv> {
        None
    }

    fn hv_mut(&mut self, _vtl: GuestVtl) -> Option<&mut ProcessorVtlHv> {
        None
    }

    fn untrusted_synic(&self) -> Option<&ProcessorSynic> {
        None
    }

    fn untrusted_synic_mut(&mut self) -> Option<&mut ProcessorSynic> {
        None
    }

    fn handle_vp_start_enable_vtl_wake(
        _this: &mut UhProcessor<'_, Self>,
        _vtl: GuestVtl,
    ) -> Result<(), UhRunVpError> {
        todo!()
    }

    fn vtl1_inspectable(_this: &UhProcessor<'_, Self>) -> bool {
        todo!()
    }
}

impl UhProcessor<'_, CcaBacked> {
    fn sysreg_write(
        &mut self,
        vtl: GuestVtl,
        reg: SystemReg,
        val: u64,
    ) -> Result<(), hcl::ioctl::Error> {
        self.runner.cca_sysreg_write(vtl, reg, val)
    }

    fn set_plane_enter(&mut self) {
        self.runner.cca_set_plane_enter();
    }

    // Copy the exit context to the entry context.
    fn preserve_plane_context(&mut self) {
        let plane_run = self.runner.cca_rsi_plane_run_mut();

        // Copy GPRs across.
        plane_run
            .entry
            .gprs
            .copy_from_slice(&plane_run.exit.gprs[..]);

        // Set the PC to the ELR_EL2 value from the exit context.
        plane_run.entry.pc = plane_run.exit.elr_el2;

        // Set GICv3 HCR to the value from the exit context.
        plane_run.entry.gicv3_hcr = plane_run.exit.gicv3_hcr;
    }

    // TODO: CCA: lots of stuff might be needed based on the TDX implementation, something akin to:
    // async fn run_vp_cca(&mut self, dev: &impl CpuIo) -> Result<(), VpHaltReason<UhRunVpError>>
}
