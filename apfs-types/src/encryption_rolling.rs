// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Encryption rolling.

use crate::{
    common::{ObjectIdentifierRaw, TransactionIdentifierRaw},
    object::ObjectHeaderRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::RangeFrom;

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

pub const ENCRYPTION_ROLLING_LENGTH: usize = 8;

pub const ENCRYPTION_ROLLING_MAGIC: &[u8; 4] = b"FLAB";

pub const ENCRYPTION_ROLLING_VERSION: u64 = 1;

pub const ENCRYPTION_ROLLING_MAX_CHECKSUM_COUNT_MASK: u64 = 0x0000ffff;
pub const ENCRYPTION_ROLLING_MAX_CHECKSUM_COUNT_SHIFT: usize = 16;

/// Encryption rolling state block header (`er_state_phys_header_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EncryptionRollingStateHeaderRaw {
    /// (`ersb_o`).
    pub object: ObjectHeaderRaw,
    /// (`ersb_magic`).
    pub magic: u32,
    /// (`ersb_version`).
    pub version: u32,
}

/// Encryption rolling state block (`er_state_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EncryptionRollingStateBlockRaw {
    /// (`ersb_header`).
    pub header: EncryptionRollingStateHeaderRaw,
    /// (`ersb_flags`).
    pub flags: u64,
    /// (`ersb_snap_xid`).
    pub snapshot_xid: TransactionIdentifierRaw,
    /// (`ersb_current_fext_obj_id`).
    pub current_file_extent_id: u64,
    /// (`ersb_file_offset`).
    pub file_offset: u64,
    /// (`ersb_progress`).
    pub progress: u64,
    /// (`ersb_total_blk_to_encrypt`).
    pub total_block_to_encrypt: u64,
    /// (`ersb_blockmap_oid`).
    pub blockmap_oid: ObjectIdentifierRaw,
    /// (`ersb_tidemark_obj_id`).
    pub tidemark_object_id: u64,
    /// (`ersb_recovery_extents_count`).
    pub recovery_extents_count: u64,
    /// (`ersb_recovery_list_oid`).
    pub recovery_list_oid: ObjectIdentifierRaw,
    /// (`ersb_recovery_length`).
    pub recovery_length: u64,
}

/// Encryption rolling state version 1 block (`er_state_phys_v1`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EncryptionRollingStateBlockV1Raw {
    /// (`ersb_header`).
    pub header: EncryptionRollingStateHeaderRaw,
    /// (`ersb_flags`).
    pub flags: u64,
    /// (`ersb_snap_xid`).
    pub snapshot_xid: TransactionIdentifierRaw,
    /// (`ersb_current_fext_obj_id`).
    pub current_file_extent_object_id: u64,
    /// (`ersb_file_offset`).
    pub file_offset: u64,
    /// (`ersb_fext_pbn`).
    pub file_extent_pbn: u64,
    /// (`ersb_paddr`).
    pub physical_address: u64,
    /// (`ersb_progress`).
    pub progress: u64,
    /// (`ersb_total_blk_to_encrypt`).
    pub total_block_to_encrypt: u64,
    /// (`ersb_blockmap_oid`).
    pub blockmap_oid: u64,
    /// (`ersb_checksum_count`).
    pub checksum_count: u32,
    /// (`ersb_reserved`).
    pub reserved: u32,
    /// (`ersb_fext_cid`).
    pub file_extent_cid: u64,
    /// (`ersb_checksum`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub checksum: [u8; 0],
}

impl DynamicSized for EncryptionRollingStateBlockV1Raw {
    // TODO maybe encryption max length is a more appropriate bound?
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

/// Encryption rolling recovery block (`er_recovery_block_phys_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EncryptionRollingRecoveryBlockRaw {
    /// (`erb_o`).
    pub object: ObjectHeaderRaw,
    /// (`erb_offset`).
    pub offset: u64,
    /// (`erb_next_oid`).
    pub next_oid: ObjectIdentifierRaw,
    /// (`erb_data`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub data: [u8; 0],
}

impl DynamicSized for EncryptionRollingRecoveryBlockRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

/// General purpose bitmap block (`gbitmap_block_phys_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct GeneralPurposeBitmapBlockRaw {
    /// (`bmb_o`).
    pub object: ObjectHeaderRaw,
    /// (`bmb_field`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub field: [u64; 0],
}

impl DynamicSized for GeneralPurposeBitmapBlockRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

/// A general purpose bitmap (`gbitmap_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct GeneralPurposeBitmapRaw {
    /// (`bm_o`).
    pub object: ObjectHeaderRaw,
    /// (`bm_tree_oid`).
    pub tree_oid: ObjectIdentifierRaw,
    /// (`bm_bit_count`).
    pub bit_count: u64,
    /// (`bm_flags`).
    pub flags: u64,
}

/// (`er_phase_t`).
pub enum EncryptionRollingPhase {
    ObjectMapRoll = 1,
    DataRoll = 2,
    SnapshotRoll = 3,
}

/// Encryption rolling checksum block sizes.
pub enum EncryptionRollingChecksumBlockSize {
    /// (`ER_512B_BLOCKSIZE`).
    FiveTwelveB = 0,
    /// (`ER_2KiB_BLOCKSIZE`).
    TwoKiB = 1,
    /// (`ER_4KiB_BLOCKSIZE`).
    FourKiB = 2,
    /// (`ER_8KiB_BLOCKSIZE`).
    EightKiB = 3,
    /// (`ER_16KiB_BLOCKSIZE`).
    SixteenKiB = 4,
    /// (`ER_32KiB_BLOCKSIZE`).
    ThirtyTwoKiB = 5,
    /// (`ER_64KiB_BLOCKSIZE`).
    SixtyFourKiB = 6,
}

bitflags! {
    /// Encryption rolling flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct EncryptionRollingFlagsRaw: u64 {
        /// (`ERSB_FLAG_ENCRYPTING`).
        const Encrypting = 0x01;
        /// (`ERSB_FLAG_DECRYPTING`).
        const Decrypting = 0x02;
        /// (`ERSB_FLAG_KEYROLLING`).
        const Keyrolling = 0x04;
        /// (`ERSB_FLAG_PAUSED`).
        const Paused = 0x08;
        /// (`ERSB_FLAG_FAILED`).
        const Failed = 0x10;
        /// (`ERSB_FLAG_CID_IS_TWEAK`).
        const CidIsTweak = 0x20;
        /// (`ERSB_FLAG_FREE_1`).
        const Free1 = 0x40;
        /// (`ERSB_FLAG_FREE_2`).
        const Free2 = 0x80;
        /// (`ERSB_FLAG_FROM_ONEKEY`).
        const FromOneKey = 0x4000;

        const _ = !0;
    }
}

impl EncryptionRollingFlagsRaw {
    pub fn block_size(&self) -> u8 {
        ((self.bits() & 0x00000F00) >> 8) as _
    }

    pub fn phase(&self) -> u8 {
        ((self.bits() & 0x00003000) >> 12) as _
    }
}
