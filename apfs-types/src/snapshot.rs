// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Snapshot metadata.
//!
//! Snapshots facilitate immutable, read-only copies of a filesystem at a given
//! point in time.

use crate::common::TimeRaw;
use crate::{
    common::{ObjectIdentifierRaw, TransactionIdentifierRaw, UuidRaw},
    filesystem::FileSystemKeyRaw,
    object::ObjectHeaderRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::Range;

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

bitflags! {
    /// Snapshot metadata flags (`snap_meta_flags`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct SnapshotMetadataFlagsRaw: u32 {
        const PendingDataless = 0x1;
        const MergeInProgress = 0x2;
        const _ = !0;
    }
}

/// Snapshot metadata record key (`j_snap_metadata_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct SnapshotMetadataRecordKeyRaw {
    /// Filesystem common header.
    ///
    /// The object ID is the snapshot's transaction identifier.
    header: FileSystemKeyRaw,
}

/// Snapshot metadata record value (`j_snap_metadata_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct SnapshotMetadataRecordValueRaw {
    /// Physical OID of the b-tree storing extents information (`extentref_tree_oid`).
    #[cfg_attr(feature = "derive", apfs(copied))]
    extent_reference_tree_oid: ObjectIdentifierRaw,

    /// Physical OID of the volume superblock (`sblock_oid`).
    #[cfg_attr(feature = "derive", apfs(copied))]
    volume_superblock_oid: ObjectIdentifierRaw,

    /// Time this snapshot was created.
    #[cfg_attr(feature = "derive", apfs(copied))]
    create_time: TimeRaw,

    /// Time this snapshot was last modified.
    #[cfg_attr(feature = "derive", apfs(copied))]
    change_time: TimeRaw,

    /// Unknown (`inum`).
    inum: u64,

    /// The type of B-tree that stores extents information (`extentref_tree_type`).
    extent_reference_tree_type: u32,

    /// Bit field containing flags for this metadata (`flags`).
    #[cfg_attr(feature = "derive", apfs(bitflags))]
    flags: SnapshotMetadataFlagsRaw,

    /// Length of the snapshot's name, including trailing NULL (`name_len`).
    name_length: u16,

    /// Snapshot's name encoded as a NULL-terminated UTF-8 string (`name`).
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    name: [u8; 0],
}

impl DynamicSized for SnapshotMetadataRecordValueRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.name_length as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for SnapshotMetadataRecordValueRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

/// Snapshot name record key (`j_snap_name_key_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct SnapshotNameRecordKeyRaw {
    /// Common filesystem header (`hdr`).
    ///
    /// Object identifier is always 0.
    header: FileSystemKeyRaw,

    /// The length of the name field, including trailing NULL (`name_len`).
    name_length: u16,

    /// The snapshot's name as a NULL-terminated UTF-8 string (`name`).
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    name: [u8; 0],
}

impl DynamicSized for SnapshotNameRecordKeyRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.name_length as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for SnapshotNameRecordKeyRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

/// Snapshot name record value (`j_snap_name_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct SnapshotNameRecordValueRaw {
    /// The last transaction identifier included in the snapshot (`snap_xid`).
    #[cfg_attr(feature = "derive", apfs(copied))]
    last_xid: TransactionIdentifierRaw,
}

/// Snapshot metadata (`snap_meta_ext_t`).
///
/// This is stored after the common object header in a block.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct SnapshotMetadataRaw {
    /// The version of this data structure (`sme_version`).
    version: u32,

    /// Flags (`sme_flags`).
    flags: u32,

    /// The snapshot's transaction identifier (`sme_snap_xid`).
    #[cfg_attr(feature = "derive", apfs(copied))]
    snapshot_xid: TransactionIdentifierRaw,

    /// The snapshot's UUID (`sme_uuid`).
    uuid: UuidRaw,

    /// Opaque metadata (`sme_token`).
    token: u64,
}

/// Snapshot metadata stored in a physical object (`snap_meta_ext_obj_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SnapshotPhysicalObjectMetadataRaw {
    /// Common object header (`smeop_o`).
    object: ObjectHeaderRaw,

    /// The metadata (`smeop_sme`).
    metadata: SnapshotMetadataRaw,
}
