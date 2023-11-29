// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Fusion.
//!
//! Fusion is a mode where a container is backed by multiple devices,
//! typically a fast SSD and a slow HD.

use crate::{
    common::{ObjectIdentifierRaw, PhysicalAddressRangeRaw, PhysicalAddressRaw},
    object::ObjectHeaderRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::RangeFrom;

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

/// Fusion writeback cache block (`fusion_wbc_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct FusionWritebackCacheBlockRaw {
    /// (`fwp_objHdr`).
    pub object: ObjectHeaderRaw,
    /// (`fwp_version`).
    pub version: u64,
    /// (`fwp_listHeadOid`).
    pub list_head_oid: ObjectIdentifierRaw,
    /// (`fwp_listTailOid`).
    pub list_tail_oid: ObjectIdentifierRaw,
    /// (`fwp_stableHeadOffset`).
    pub stable_head_offset: u64,
    /// (`fwp_stableTailOffset`).
    pub stable_tail_offset: u64,
    /// (`fwp_listBlocksCount`).
    pub list_blocks_count: u32,
    /// (`fwp_reserved`).
    pub reserved: u32,
    /// (`fwp_usedByRC`).
    pub used_by_rc: u64,
    /// (`fwp_rcStash`).
    pub rc_stash: PhysicalAddressRangeRaw,
}

/// Fusion writeback cache list entry (`fusion_wbc_list_entry_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct FusionWritebackCacheListEntryRaw {
    /// (`fwle_wbcLba`).
    pub writeback_cache_lba: PhysicalAddressRaw,
    /// (`fwle_targetLba`).
    pub target_lba: PhysicalAddressRaw,
    /// (`fwle_length`).
    pub length: u64,
}

/// Fusion writeback cache list block (`fusion_wbc_list_phys_t`).
///
/// Keeps track of data from the hard drive that's cached on SSD.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct FusionWritebackCacheListBlockRaw {
    /// (`fwlp_objHdr`).
    pub object: ObjectHeaderRaw,
    /// (`fwlp_version`).
    pub version: u64,
    /// (`fwlp_tailOffset`).
    pub tail_offset: u64,
    /// (`fwlp_indexBegin`).
    pub index_begin: u32,
    /// (`fwlp_indexEnd`).
    pub index_end: u32,
    /// (`fwlp_indexMax`).
    pub index_max: u32,
    /// (`fwlp_reserved`).
    pub reserved: u32,
    /// (`fwlp_listEntries`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub entries: [FusionWritebackCacheListEntryRaw; 0],
}

impl DynamicSized for FusionWritebackCacheListBlockRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

/// Fusion middle-tree key (`fusion_mt_key_t`).
pub type FusionMiddleTreeKey = PhysicalAddressRaw;

bitflags! {
    /// Fusion middle-tree flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct FusionMiddleTreeFlagsRaw: u32 {
        const Dirty = 1;
        const Tenant = 2;
        const _ = !0;
    }
}

/// Fusion middle-tree value (`fusion_mt_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct FusionMiddleTreeValueRaw {
    /// (`fmv_lba`).
    pub lba: PhysicalAddressRaw,
    /// (`fmv_length`).
    pub length: u32,
    /// (`fmv_flags`).
    pub flags: FusionMiddleTreeFlagsRaw,
}
