// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The module should include the definitions of data structures according to CCA specification.

/// Ioctl type defined by Linux.
pub const CCA_CMD_GET_REPORT0_IOC_TYPE: u8 = b'T';

/// Size of the CCA attestation report.
pub const CCA_REPORT_SIZE: usize = 0x400;