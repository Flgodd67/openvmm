// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Support for loading a TMK into VM memory.

use anyhow::Context as _;
use fs_err::File;
use guestmem::GuestMemory;
use hvdef::Vtl;
use loader::importer::GuestArch;
use loader::importer::ImageLoad;
use loader::importer::X86Register;
use object::Endianness;
use object::Object;
use object::ObjectSection;
use object::ObjectSegment as _;
use std::fmt::Debug;
use std::sync::Arc;
use virt::VpIndex;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::ProcessorTopology;
use vm_topology::processor::aarch64::Aarch64Topology;
use vm_topology::processor::x86::X86Topology;
use zerocopy::FromBytes as _;
use zerocopy::IntoBytes;

use nix::{
    sys::{
        mman::{MapFlags, ProtFlags, mmap},
        statfs::statfs,
    },
    unistd::{ftruncate, mkstemp, unlink},
};
use std::{
    num::NonZeroUsize,
    os::unix::{fs::FileExt, io::FromRawFd},
    path::Path,
};


/// Loads a TMK, returning the initial registers for the BSP.
#[cfg_attr(not(guest_arch = "x86_64"), expect(dead_code))]
pub fn load_x86(
    offset_addr: Option<u64>,
    memory_layout: &MemoryLayout,
    guest_memory: &GuestMemory,
    processor_topology: &ProcessorTopology<X86Topology>,
    caps: &virt::x86::X86PartitionCapabilities,
    tmk: &File,
    test: &TestInfo,
) -> anyhow::Result<Arc<virt::x86::X86InitialRegs>> {
    let mut loader = vm_loader::Loader::new(guest_memory.clone(), memory_layout, Vtl::Vtl0);
    let load_info = load_common(offset_addr, &mut loader, tmk, test)?;

    let page_table_base = load_info.next_available_address;
    let page_tables = page_table::x64::build_page_tables_64(
        page_table_base,
        0,
        page_table::IdentityMapSize::Size4Gb,
        None,
    );
    loader
        .import_pages(
            page_table_base >> 12,
            page_tables.len() as u64 >> 12,
            "page_tables",
            loader::importer::BootPageAcceptance::Exclusive,
            &page_tables,
        )
        .context("failed to import page tables")?;

    let gdt_base = page_table_base + page_tables.len() as u64;
    loader::common::import_default_gdt(&mut loader, gdt_base >> 12)
        .context("failed to import gdt")?;

    let mut import_reg = |reg| {
        loader
            .import_vp_register(reg)
            .context("failed to set register")
    };
    import_reg(X86Register::Cr0(x86defs::X64_CR0_PG | x86defs::X64_CR0_PE))?;
    import_reg(X86Register::Cr3(page_table_base))?;
    import_reg(X86Register::Cr4(x86defs::X64_CR4_PAE))?;
    import_reg(X86Register::Efer(
        x86defs::X64_EFER_SCE
            | x86defs::X64_EFER_LME
            | x86defs::X64_EFER_LMA
            | x86defs::X64_EFER_NXE,
    ))?;
    import_reg(X86Register::Rip(load_info.entrypoint))?;
    import_reg(X86Register::Rsi(load_info.param))?;

    let regs = vm_loader::initial_regs::x86_initial_regs(
        &loader.initial_regs(),
        caps,
        &processor_topology.vp_arch(VpIndex::BSP),
    );
    Ok(regs)
}

pub unsafe fn mmap_hugetlbfs(htlbfs_mount_dir: &Path, size: u64) -> Result<u64, String> {
    // Perform preliminary checks on the request size.
    if size == 0{
        return Err("A mapping of size 0 is not permitted".to_string());
    }

    let size_as_usize = usize::try_from(size).map_err(|_| {
        format!("The request size of {size} bytes is too large for this platform's address space")
    })?;

    let size_as_i64 = i64::try_from(size).map_err( |_| {
        format!("The request size of {size} bytes is too large for an i64 offset")
    })?;

    let non_zero_size =
        NonZeroUsize::new(size_as_usize).expect("Size was already checked to be non-zero");

    let mpath = htlbfs_mount_dir.join("kvmtools-XXXXXX");
    if mpath.exists() {
        std::fs::remove_file(&mpath).map_err(|e| {
            format!(
                "Failed to remove existing file at '{}': {}",
                mpath.display(),
                e
            )
        })?;
    }

    let sfs = statfs(htlbfs_mount_dir).map_err(|e| {
        format!(
            "Failed to stat filesystem at '{}': {}",
            htlbfs_mount_dir.display(),
            e
        )
    })?;

    // Verify that the filesystem is actually hugetlbfs.
    if sfs.filesystem_type() != nix::sys::statfs::HUGETLBFS_MAGIC {
        return Err(format!(
            "The path '{}' is not on a hugetlbfs filesystem",
            htlbfs_mount_dir.display()
        ));
    }

    // Validate the huge page size (block size) against the request mapping size.
    let blk_size = sfs.block_size() as u64;
    if blk_size == 0 || blk_size > size {
        return Err(format!(
            "Invalid hugetlbfs page size ({blk_size} bytes) for the requested memory size ({size} bytes)"
        ));
    }

    // Create a unique tempory file using the user_provided template.
    let (fd, mpath) = mkstemp(&mpath).map_err(| e | {
        format!(
            "Failed to create temporary file using template '{}': {}",
            mpath.display(),
            e
        )
    })?;

    // --- Start of RAII-managed resource scope ---
    let file = unsafe { std::fs::File::from_raw_fd(fd)};

    // Immediately unlink the file from the filesystem
    unlink(&mpath).map_err(|e| {
        format!(
            "Failed to unlink temporary file at '{}': {}",
            mpath.display(),
            e
        )
    })?;

    // Set the file size to the desired mapping size.
    ftruncate(&file, size_as_i64)
        .map_err(|e| format!("Failed to truncate temporary file to {size} bytes: {e}"))?;

    // Memory-map the file
    let addr = unsafe {
        mmap(
            None,
            non_zero_size, 
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
            &file,
            0,
        )
    }.map_err(| e | {
        format!("Failed to memory-map {size} bytes: {e}")
    })?;

    // --- End of RAII-managed resource scope ---

    // Return the memory address cast to a u64 integer.
    Ok(addr.as_ptr() as u64)
}

pub unsafe fn virt_to_phys(vaddr: u64) -> Result<u64, String> {
    // Constants based on the kernel's pagemap documentation.
    const PFN_BITS: u64 = 55;
    const PFN_MASK: u64 = (1 <<PFN_BITS) - 1;
    const PAGE_PRESENT_BIT: u64 = 1 << 63;
    const PAGEMAP_ENTRY_SIZE: u64 = size_of::<u64>() as u64;

    // Get the system's page size. This is more reliable than using a hardcoded value.
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as u64;

    if page_size == 0 {
        return Err("Could not determine system page size".to_string());
    }

    // Open the pagemap file for the current process.
    let pagemap_file = std::fs::File::open("/proc/self/pagemap").map_err( | e | {
        format!("Failed to open /proc/self/pagemap (requires root or CAP_SYS_ADMIN): {e}")
    })?;

    let offset = (vaddr/page_size) * PAGEMAP_ENTRY_SIZE;

    let mut entry_bytes = [0u8; 8];

    pagemap_file
        .read_exact_at(&mut entry_bytes, offset)
        .map_err(|e| format!("Failed to read from /proc/self/pagemap at offset {offset}: {e}"))?;

    let pagemap_entry = u64::from_ne_bytes(entry_bytes);

    if (pagemap_entry & PAGE_PRESENT_BIT) == 0 {
        return Err(format!(
            "Page for virtual addree {vaddr:#x} is not present in RAM (swapped out or not mapped)"
        ));
    }

    // The lower 55 bits contain the PFN
    let pfn = pagemap_entry & PFN_MASK;
    Ok(pfn * page_size);

}

#[cfg_attr(not(guest_arch = "aarch64"), expect(dead_code))]
pub fn load_aarch64(
    load_offset: Option<u64>,
    memory_layout: &MemoryLayout,
    guest_memory: &GuestMemory,
    processor_topology: &ProcessorTopology<Aarch64Topology>,
    caps: &virt::aarch64::Aarch64PartitionCapabilities,
    tmk: &File,
    test: &TestInfo,
) -> anyhow::Result<Arc<virt::aarch64::Aarch64InitialRegs>> {
    let mut loader = vm_loader::Loader::new(guest_memory.clone(), memory_layout, Vtl::Vtl0);
    let load_info = load_common(load_offset, &mut loader, tmk, test)?;

    let mut import_reg = |reg| {
        loader
            .import_vp_register(reg)
            .context("failed to set register")
    };

    import_reg(loader::importer::Aarch64Register::Pc(load_info.entrypoint))?;
    import_reg(loader::importer::Aarch64Register::X0(load_info.param))?;
    let regs = vm_loader::initial_regs::aarch64_initial_regs(
        &loader.initial_regs(),
        caps,
        &processor_topology.vp_arch(VpIndex::BSP),
    );

    Ok(regs)
}

fn load_common<R: Debug + GuestArch>(
    offset_addr: Option<u64>,
    loader: &mut vm_loader::Loader<'_, R>,
    tmk: &File,
    test: &TestInfo,
) -> anyhow::Result<LoadInfo> {
    let load_info = loader::elf::load_static_elf(
        loader,
        &mut &*tmk,
        0,
        offset_addr.unwrap_or(0x98000000), // 0x200000
        false,
        loader::importer::BootPageAcceptance::Exclusive,
        "tmk",
    )
    .context("failed to load tmk")?;

    let start_input = tmk_protocol::StartInput {
        command: crate::run::COMMAND_ADDRESS,
        test_index: test.index,
    };

    let start_input_addr = load_info.next_available_address;

    loader.import_pages(
        start_input_addr >> 12,
        1,
        "start_input",
        loader::importer::BootPageAcceptance::Exclusive,
        start_input.as_bytes(),
    )?;

    Ok(LoadInfo {
        entrypoint: load_info.entrypoint,
        param: start_input_addr,
        next_available_address: start_input_addr + 0x1000,
    })
}

struct LoadInfo {
    entrypoint: u64,
    param: u64,
    next_available_address: u64,
}

#[derive(Clone)]
pub struct TestInfo {
    pub name: String,
    pub index: u64,
}

/// Enumerate the tests from a TMK binary.
///
/// The test definitions are stored as an array of
/// [`tmk_protocol::TestDescriptor64`] in the "tmk_tests" section of the binary.
pub fn enumerate_tests(tmk: &File) -> anyhow::Result<Vec<TestInfo>> {
    let reader = object::ReadCache::new(tmk);
    let file: object::read::elf::ElfFile64<'_, Endianness, _> =
        object::read::elf::ElfFile::parse(&reader).context("failed to parse TMK")?;

    let mut relocs = file
        .dynamic_relocations()
        .context("failed to find dynamic relocations")?
        .collect::<Vec<_>>();
    relocs.sort_by_key(|&(a, _)| a);

    // Relocate address `v` that was loaded from address `addr`.
    let reloc = |addr, v: u64| {
        let r = relocs.binary_search_by_key(&addr, |&(a, _)| a);
        match r {
            Ok(i) => {
                let reloc = &relocs[i].1;
                v.wrapping_add_signed(reloc.addend())
            }
            Err(_) => v,
        }
    };

    let section = file
        .section_by_name("tmk_tests")
        .context("failed to find tmk_tests section")?;
    let data = section.data()?;
    let descriptors = <[tmk_protocol::TestDescriptor64]>::ref_from_bytes(data)
        .ok()
        .context("failed to parse tmk_tests section")?;
    let mut tests = Vec::with_capacity(descriptors.len());
    for (i, t) in descriptors.iter().enumerate() {
        let name_address = reloc(
            section.address() + (i * size_of::<tmk_protocol::TestDescriptor64>()) as u64,
            t.name,
        );
        let name = file
            .segments()
            .find_map(|s| s.data_range(name_address, t.name_len).transpose())
            .context("failed to find name for test")?
            .context("failed to parse tmk")?;
        let name = core::str::from_utf8(name).context("failed to parse test name")?;

        tests.push(TestInfo {
            name: name.to_string(),
            index: i as u64,
        });
    }

    Ok(tests)
}
