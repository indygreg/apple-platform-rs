// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Object maps

use {
    crate::{
        common::{
            ObjectIdentifierRaw, PhysicalAddressRaw, TransactionIdentifierRaw,
            VirtualObjectIdentifierRaw,
        },
        object::{ObjectHeaderRaw, ObjectTypeValueRaw},
    },
    bitflags::bitflags,
    core::cmp::Ordering,
};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

bitflags! {
    /// Flags for an object map block.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ObjectMapFlagsRaw: u32 {
        /// Object map doesn't support snapshots (`OMAP_MANUALLY_MANAGED`).
        ///
        /// Only valid on the container's object map.
        const ManuallyManaged = 0x01;

        /// Unencrypted to encrypted storage transition ibn progress (`OMAP_ENCRYPTING`).
        const Encrypting = 0x02;

        /// Encrypted to unencrypted storage transition in progress(`OMAP_DECRYPTING`).
        const Decrypting = 0x04;

        /// Encrypted storage is rotating encryption keys (`OMAP_KEYROLLING`).
        const Keyrolling = 0x08;

        /// Tracks encryption configuration (`OMAP_CRYPTO_GENERATION`).
        ///
        /// Related to [ObjectMapValueFlagsRaw::CryptoGeneration].
        const CryptoGeneration = 0x10;

        const _ = !0;
    }
}

/// An object map (`omap_phys_t`).
///
/// An object map uses a b-tree to store a mapping from virtual object IDs
/// and transaction IDs to addresses where the objects are stored.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapBlockRaw {
    /// The object's header (`om_o`).
    pub object: ObjectHeaderRaw,

    /// The object map's flags (`om_flags`).
    pub flags: ObjectMapFlagsRaw,

    /// The number of snapshots that this object map has (`om_snap_count`).
    pub snapshot_count: u32,

    /// The type of tree being used for object mappings (`om_tree_type`).
    pub tree_type: ObjectTypeValueRaw,

    /// The type of tree being used for snapshots (`om_snapshot_tree_type`).
    pub snapshot_tree_type: ObjectTypeValueRaw,

    /// The object identifier of the tree being used for object mappings (`om_tree_oid`).
    pub tree_oid: ObjectIdentifierRaw,

    /// The object identifier of the tree being used to hold snapshot information (`om_snapshot_tree_oid`).
    ///
    /// Tree keys are transaction IDs.
    /// Tree values are [ObjectMapSnapshotRaw].
    pub snapshot_tree_oid: ObjectIdentifierRaw,

    /// The transaction identifier of the most recent snapshot that's stored in this map (`om_most_recent_snap`).
    pub most_recent_snapshot_identifier: TransactionIdentifierRaw,

    /// The smallest transaction identifier for an in-progress revert (`om_pending_revert_min`).
    pub pending_revert_minimum_identifier: TransactionIdentifierRaw,

    /// The largest transaction identifier for an in-progress revert (`om_pending_revert_max`).
    pub pending_revert_maximum_identifier: TransactionIdentifierRaw,
}

/// Key used to access an entry in the object map (`omap_key_t`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapKeyRaw {
    /// The object identifier (`ok_oid`).
    pub oid: VirtualObjectIdentifierRaw,
    /// The transaction identifier (`ok_xid`).
    pub xid: TransactionIdentifierRaw,
}

// Sorted by OID first then XID.

impl Ord for ObjectMapKeyRaw {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.oid, self.xid).cmp(&(other.oid, other.xid))
    }
}

impl PartialOrd for ObjectMapKeyRaw {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

bitflags! {
    /// Flags for an [ObjectMapValueRaw].
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ObjectMapValueFlagsRaw: u32 {
        /// The object has been deleted and this mapping is a placeholder (`OMAP_VAL_DELETED`).
        const Deleted = 0x01;

        /// This mapping shouldn't be replaced when the object is updated (`OMAP_VAL_SAVED`)
        ///
        /// Apple's docs say this flag is never used.
        ///
        /// Apparently only used in object maps having [ObjectMapFlagsRaw::ManuallyManaged] set.
        const Saved = 0x02;

        /// The object is encrypted (`OMAP_VAL_ENCRYPTED`).
        const Encrypted = 0x04;

        /// The object is stored without the common object header (`OMAP_VAL_NOHEADER`).
        const NoHeader = 0x08;

        /// Tracks encryption configuration (`OMAP_VAL_CRYPTO_GENERATION`).
        ///
        /// This is set in tandem with [ObjectMapFlagsRaw::CryptoGeneration] to indicate
        /// changes in crypto configuration. If this flag doesn't match the value
        /// on the object map, it means the crypto configurations are out of sync and
        /// we're still waiting on things to take up the new configuration.
        const CryptoGeneration = 0x10;

        const _ = !0;
    }
}

/// A value in the object map (`omap_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapValueRaw {
    /// A bit field of flags (`ov_flags`).
    pub flags: ObjectMapValueFlagsRaw,

    /// Size of the object (`ov_size`).
    ///
    /// Must be a multiple of the container's block size.
    ///
    /// If the object is smaller than the container's block size, the
    /// value here is rounded up to that block size.
    pub size_bytes: u32,

    /// The address of the object (`ov_paddr`).
    pub address: PhysicalAddressRaw,
}

bitflags! {
    /// Flags used to record the state of an object map snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ObjectMapSnapshotFlagsRaw: u32 {
        /// The snapshot has been deleted (`OMAP_SNAPSHOT_DELETED`).
        const Deleted = 0x01;

        /// The snapshot has been deleted as part of a revert (`OMAP_SNAPSHOT_REVERTED`).
        const Reverted = 0x02;
    }
}

/// Information about a snapshot of an object map (`omap_snapshot_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapSnapshotRaw {
    /// The snapshot's flags (`oms_flags`).
    pub flags: ObjectMapSnapshotFlagsRaw,

    /// Reserved (`oms_pad`).
    ///
    /// Populate with 0s for new snapshots and preserve values when modifying.
    pub pad: u32,

    /// Reserved (`oms_oid`).
    ///
    /// Populate with 0s for new snapshots and preserve values when modifying.
    pub oid: ObjectIdentifierRaw,
}
