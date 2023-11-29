// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! APFS volumes.

use crate::common::{PhysicalObjectIdentifierRaw, TimeRaw, VirtualObjectIdentifierRaw};
use crate::encryption::WrappedMetaCryptoStateRaw;
use crate::object::ObjectTypeValueRaw;
use crate::{
    common::{ObjectIdentifierRaw, TransactionIdentifierRaw, UuidRaw},
    object::ObjectHeaderRaw,
};
use bitflags::bitflags;

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::{common::*, container::*, data_stream::*, filesystem::*, object::*};

/// Information about a program that modified a volume (`apfs_modified_by_t`).
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ApfsModifiedByRaw {
    /// A string that identifies the program and its version (`id`).
    pub id: [u8; 32],

    /// The time the program last modified this volume (`id`).
    pub timestamp: TimeRaw,

    /// The last transaction ID that's part of this program's modifications (`id`).
    pub last_transaction: TransactionIdentifierRaw,
}

bitflags! {
    /// Volume flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct VolumeFlagsRaw: u64 {
        /// The volume isn't encrypted (`APFS_FS_UNENCRYPTED`).
        const Unencrypted = 0x01;

        /// Reserved (`APFS_FS_RESERVED_2`).
        ///
        /// Don't set but preserve.
        const Reserved2 = 0x02;

        /// Reserved (`APFS_FS_RESERVED_4`).
        ///
        /// Don't set but preserve.
        const Reserved4 = 0x04;

        /// Files on the volume are all encrypted using the volume encryption key (VEK) (`APFS_FS_ONEKEY`).
        ///
        /// Only set on macOS volumes since iOS always uses per-file encryption.
        const OneKey = 0x08;

        /// The volume has run out of allocated space on the solid-state drive (`APFS_FS_SPILLEDOVER`).
        const SpilledOver = 0x10;

        /// The volume has spilled over and the spillover cleaner must be run (`APFS_FS_RUN_SPILLOVER_CLEANER`).
        const RunSpilloverCleaner = 0x20;

        /// he volume's extent reference tree is always consulted when deciding whether to overwrite an extent (`APFS_FS_ALWAYS_CHECK_EXTENTREF`).
        const AlwaysCheckExtentRef = 0x40;

        /// Reserved (`APFS_FS_RESERVED_80`).
        const Reserved80 = 0x80;

        /// Reserved (`APFS_FS_RESERVED_100`).
        const Reserved100 = 0x100;

        /// A bit mask of all encryption related volume flags.
        const CryptoFlags = (
            VolumeFlagsRaw::Unencrypted.bits() |
            VolumeFlagsRaw::Reserved2.bits() |
            VolumeFlagsRaw::OneKey.bits()
        );

        const _ = !0;
    }
}

/// used to indicate a volume's role.
///
/// A volume has at most 1 role.
///
/// The roles using the lower 6 bits and [Self::Data] plus
/// [Self::Baseband] are supported on all versions of macOS and iOS.
/// The other roles in the upper 10 bits are only supported on macOS 10.15
/// and iOS 13 and later.
#[repr(u16)]
pub enum VolumeRole {
    /// The volume has no defined role (`APFS_VOL_ROLE_NONE`).
    ///
    /// No volume flags should be set for this value.
    None = 0x0,

    /// The volume contains a root directory for the system (`APFS_VOL_ROLE_SYSTEM`).
    ///
    /// On iOS and macOS 10.15 and later, system volumes are mounted read-only.
    System = 0x01,

    /// The volume contains users home directories (`APFS_VOL_ROLE_USER`).
    User = 0x02,

    /// The volume contains a recovery system (`APFS_VOL_ROLE_RECOVERY`).
    ///
    /// This is used as a recovery partition.
    Recovery = 0x04,

    /// The volume is used as swap space for virtual memory (`APFS_VOL_ROLE_VM`).
    ///
    /// Likely mounted to `/var/vm`.
    VirtualMemory = 0x08,

    /// The volume contains files needed to boot from an encrypted volume (`APFS_VOL_ROLE_PREBOOT`).
    Preboot = 0x10,

    /// The volume is used by the OS installer (`APFS_VOL_ROLE_INSTALLER`).
    Installer = 0x20,

    /// The volume contains mutable data (`APFS_VOL_ROLE_DATA`).
    ///
    /// iOS and macOS 10.15+.
    ///
    /// Contains both user data and mutable system data.
    Data = 1 << 6,

    /// The volume is used by the radio firmware (`APFS_VOL_ROLE_BASEBAND`).
    ///
    /// Only used on iOS.
    Baseband = 2 << 6,

    /// The volume is used by the software update mechanism (`APFS_VOL_ROLE_UPDATE`).
    ///
    /// Only used on iOS.
    Update = 3 << 6,

    /// The volume is used to manage OS access to secure user data (`APFS_VOL_ROLE_XART`).
    ///
    /// Only used on iOS.
    Xart = 4 << 6,

    /// The volume is used for firmware data (`APFS_VOL_ROLE_HARDWARE`).
    ///
    /// Only used on iOS.
    Hardware = 5 << 6,

    /// The volume is used by Time Machine to store backups (`APFS_VOL_ROLE_BACKUP`).
    ///
    /// Only used on macOS.
    Backup = 6 << 6,

    /// Reserved (`APFS_VOL_ROLE_RESERVED_7`).
    Reserved7 = 7 << 6,

    /// Reserved (`APFS_VOL_ROLE_RESERVED_8`).
    Reserved8 = 8 << 6,

    /// This volume is used to store enterprise-managed data (`APFS_VOL_ROLE_ENTERPRISE`).
    Enterprise = 9 << 6,

    /// Reserved (`APFS_VOL_ROLE_RESERVED_10`).
    Reserved10 = 10 << 6,

    /// This volume is used to store system data used before login (`APFS_VOL_ROLE_PRELOGIN`).
    ///
    /// Only used on macOS.
    ///
    /// Prelogin volumes allow the system to boot to the login screen
    /// so the user can enter a password to decrypt additional volumes.
    Prelogin = 11 << 6,
}

bitflags! {
    /// Volume optional feature flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct VolumeOptionalFeatureFlagsRaw: u64 {
        /// Reserved (`APFS_FEATURE_DEFRAG_PRERELEASE`).
        ///
        /// Enabled a pre-release version of a defragmentation system. Avoid setting
        /// to prevent data corruption.
        const DefragPrerelease = 0x01;

        /// The volume has hardlink map records (`APFS_FEATURE_HARDLINK_MAP_RECORDS`).
        const HardlinkMapRecords = 0x02;

        /// The volume supports defragmentation (`APFS_FEATURE_DEFRAG`).
        ///
        /// Ignored prior to macOS 10.14.
        const Defrag = 0x04;

        /// This volume updates file access times every time the file is read (`APFS_FEATURE_STRICTATIME`).
        ///
        /// If set, the [InodeRecordValueRaw::access_time] field is updated every
        /// time the file is read. Otherwise, that field is updated only if its value
        /// is older than the inode's modification time field.
        const StrictAtime = 0x08;

        /// This volume supports mounting a system and data volume as a single user-visible volume (`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`).
        ///
        /// Used by macOS 10.15 and later to combine a read-only system volume with a
        /// read-write data volume. Both volumes have the same volume group ID.
        ///
        /// If set, the volume in the data role uses inode numbers less than
        /// [INODE_UNIFIED_ID_SPACE_MARK] and the system role uses inode numbers
        /// [INODE_UNIFIED_ID_SPACE_MARK] or larger. The first 16 inodes in each
        /// range are reserved.
        const VolumeGroupSystemInodeSpace = 0x10;

        const _ = !0;
    }
}

bitflags! {
    /// Incompatible volume feature flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct VolumeIncompatibleFeatureFlagsRaw: u64 {
        /// Filenames on this volume are case insensitive (`APFS_INCOMPAT_CASE_INSENSITIVE`).
        const CaseInsensitive = 0x01;

        /// At least one snapshot with no data exists for this volume (`APFS_INCOMPAT_DATALESS_SNAPS`).
        const DatalessSnaps = 0x02;

        /// This volume's encryption has changed keys at least once (`APFS_INCOMPAT_ENC_ROLLED`).
        const EncRolled = 0x04;

        /// Filenames on this volume are normalization insensitive (`APFS_INCOMPAT_NORMALIZATION_INSENSITIVE`).
        ///
        /// This is related to the hashing of directory entry keys.
        const NormalizationInsensitive = 0x08;

        /// This volume is being restored, or a restore operation to this volume was uncleanly aborted (`APFS_INCOMPAT_INCOMPLETE_RESTORE`).
        const IncompleteRestore = 0x10;

        /// This volume can't be modified (`APFS_INCOMPAT_SEALED_VOLUME`).
        const SealedVolume = 0x20;

        /// Reserved (`APFS_INCOMPAT_RESERVED_40`).
        const Reserved40 = 0x40;
    }
}

/// Magic value in APFS volume header (`APFS_MAGIC`).
///
/// In hex dumps it is `APSB`, which is *Apple file system superblock*.
pub const VOLUME_MAGIC: &[u8; 4] = b"BSPA";

/// Maximum number of volume modified by entries (`APFS_MAX_HIST`).
pub const VOLUME_MAX_HISTORY: usize = 8;

/// Maximum length of a volume's name.
pub const VOLUME_NAME_LENGTH: usize = 256;

/// APFS volume superblock (`apfs_superblock_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct VolumeSuperblockRaw {
    /// The object's header (`apfs_o`).
    pub object: ObjectHeaderRaw,
    /// Magic value (`apfs_magic`).
    ///
    /// Should be [VOLUME_MAGIC].
    pub magic: [u8; 4],

    /// The index of this volume in the container's volume array (`apfs_fs_index`).
    ///
    /// Corresponds to [ContainerSuperblockRaw::volume_oids].
    ///
    /// When a volume is being deleted, it is removed from the container's
    /// volume array before this object is destroyed. So the index/OID stored in the
    /// container superblock may have already been recycled for another volume
    /// if this one is currently being destroyed.
    pub fs_index: u32,

    /// A bit field of the optional features being used by this volume (`apfs_features`).
    ///
    /// If an implementation does not support a feature in this set, the volume
    /// can continue to be mounted.
    pub optional_features: VolumeOptionalFeatureFlagsRaw,

    /// A bit field of the read-only compatible features being used by this volume (`apfs_readonly_compatible_features`).
    ///
    /// If an implementation sees an unknown flag in this feature set, it should
    /// mount the volume read-only.
    pub readonly_compatible_features: u64,

    /// A bit field of the backward-incompatible features being used by this volume (`apfs_incompatible_features`).
    ///
    /// If an implementation sees an unknown or unsupported flag in this feature
    /// set, it should refuse to mount the volume.
    pub incompatible_features: VolumeIncompatibleFeatureFlagsRaw,

    /// The time that this volume was last unmounted (`apfs_unmount_time`).
    pub unmount_time: TimeRaw,

    /// The number of blocks that have been reserved for this volume to allocate (`apfs_fs_reserve_block_count`).
    pub reserved_block_count: u64,

    /// The maximum number of blocks that this volume can allocate (`apfs_fs_quota_block_count`).
    pub quota_block_count: u64,

    /// The number of blocks currently allocated for this volume's file system (`apfs_fs_alloc_count`).
    pub allocated_block_count: u64,

    /// Information about the key used to encrypt metadata for this volume (`apfs_meta_crypto`).
    ///
    /// On macOS, the volume encryption key (VEK) is used to encrypt metadata.
    pub metadata_encryption_state: WrappedMetaCryptoStateRaw,

    /// The type of the root file-system tree (`apfs_root_tree_type`).
    ///
    /// Typically a virtual object pointing to a B-tree root node with a
    /// subtype of [ObjectType::FilesystemTree].
    pub root_tree_type: ObjectTypeValueRaw,

    /// The type of the extent-reference tree (`apfs_extentref_tree_type`).
    ///
    /// Typically a physical object for a B-tree root node with subtype
    /// of [ObjectType::ExtentReferenceTree].
    pub extent_reference_tree_type: ObjectTypeValueRaw,

    /// The type of the snapshot metadata tree (`apfs_snap_meta_tree_type`).
    ///
    /// Typically a physical object for a B-tree root node with a subtype
    /// of [ObjectType::SnapshotMetadataTree].
    pub snapshot_metadata_tree_type: ObjectTypeValueRaw,

    /// The object identifier of the volume's object map (`apfs_omap_oid`).
    pub object_map_oid: PhysicalObjectIdentifierRaw,

    /// The object identifier of the root file-system tree (`apfs_root_tree_oid`).
    pub root_tree_oid: ObjectIdentifierRaw,

    /// The object identifier of the extent-reference tree (`apfs_extentref_tree_oid`).
    pub extent_reference_tree_oid: ObjectIdentifierRaw,

    /// The object identifier of the snapshot metadata tree (`apfs_snap_meta_tree_oid`).
    ///
    /// When a snapshot is created, the current extent-reference tree is moved to
    /// the snapshot. A new, empty extent-reference tree becomes the new value
    /// of this field.
    pub snapshot_metadata_tree_oid: ObjectIdentifierRaw,

    /// The transaction identifier of a snapshot that the volume will revert to (`apfs_revert_to_xid`).
    ///
    /// When mounting a volume, if the value is non-0, revert to the specified
    /// snapshot by deleting all snapshots after this transaction ID and then setting
    /// this field to 0.
    pub revert_to_xid: TransactionIdentifierRaw,

    /// The object identifier of a volume superblock that the volume will revert to (`apfs_revert_to_sblock_oid`).
    ///
    /// When mounting a volume and [Self::revert_to_xid] is non-0, ignore the
    /// value of this field. Otherwise revert to the specified volume superblock.
    pub revert_to_superblock_oid: PhysicalObjectIdentifierRaw,

    /// The next identifier that will be assigned to a file-system object in this volume (`apfs_next_obj_id`).
    pub next_object_identifier: ObjectIdentifierRaw,

    /// The number of regular files in this volume (`apfs_num_files`).
    pub number_files: u64,

    /// The number of directories in this volume (`apfs_num_directories`).
    pub number_directories: u64,

    /// The number of symbolic links in this volume (`apfs_num_symlinks`).
    pub number_symlinks: u64,

    /// The number of other files in this volume (`apfs_num_other_fsobjects`).
    ///
    /// Includes all files not counted by the above 3 fields.
    pub number_other: u64,

    /// The number of snapshots in this volume (`apfs_num_snapshots`).
    pub number_snapshots: u64,

    /// The total number of blocks that have been allocated by this volume (`apfs_total_blocks_alloced`).
    ///
    /// This value increases when blocks are allocated but never decreases when they
    /// are freed.
    ///
    /// If there are no files in the volume, value should match
    /// [Self::total_blocks_freed].
    pub total_blocks_allocated: u64,

    /// The total number of blocks that have been freed by this volume (`apfs_total_blocks_freed`).
    ///
    /// Not modified when blocks are allocated. Increased when blocks are freed.
    pub total_blocks_freed: u64,

    /// The universally unique identifier for this volume (`apfs_vol_uuid`).
    pub volume_id: UuidRaw,

    /// The time that this volume was last modified (`apfs_last_mod_time`).
    pub last_modification_time: TimeRaw,

    /// The volume's flags (`apfs_fs_flags`).
    pub flags: VolumeFlagsRaw,

    /// Information about the software that created this volume (`apfs_formatted_by`).
    ///
    /// Only set at volume creation time.
    pub formatted_by: ApfsModifiedByRaw,

    /// Information about the software that has modified this volume (`apfs_modified_by`).
    ///
    /// The newest element is stored at index 0.
    ///
    /// When updating a volume, shift existing elements right by 1 and
    /// discard the last item.
    ///
    /// If the new latest modified entry would be identical to the existing
    /// one, it is permitted to either copy the latest entry or do nothing.
    ///
    /// Empty entries should be all 0s.
    pub modified_by: [ApfsModifiedByRaw; VOLUME_MAX_HISTORY],

    /// The name of the volume, represented as a null-terminated UTF-8 string (`apfs_volname`).
    pub volume_name: [u8; VOLUME_NAME_LENGTH],

    /// The next document identifier that will be assigned (`apfs_next_doc_id`).
    ///
    /// Document identifiers cannot be recycled.
    pub next_document_identifier: u32,

    /// The role of this volume within the container (`apfs_role`).
    ///
    /// Values are [VolumeRole].
    pub role: u16,

    /// Reserved (`reserved`).
    ///
    /// 0s for new volume. Preserved during modifications.
    pub reserved_after_role: u16,

    /// The transaction identifier of the snapshot to root from (`apfs_root_to_xid`).
    ///
    /// 0 to root normally.
    pub root_to_xid: TransactionIdentifierRaw,

    /// Object holding encryption rolling state of this volume.
    ///
    /// 0 means encryption rolling isn't in progress.
    pub encryption_rolling_state_oid: ObjectIdentifierRaw,

    /// The largest object identifier used by this volume (`apfs_cloneinfo_id_epoch`).
    ///
    /// If 0, all information stored using [InodeFlagsRaw::WasEverCloned] is valid.
    /// Otherwise, OIDs before this value may not have recorded that inode flag
    /// correctly.
    ///
    /// If both this and [Self::cloneinfo_xid] are 0, this structure was
    /// likely created by an older implementation of APFS with the buggy
    /// behavior.
    ///
    /// Added in macOS 10.13.3.
    pub cloneinfo_id_epoch: ObjectIdentifierRaw,

    /// A transaction identifier tracking the was ever cloned epoch (`apfs_cloneinfo_xid`).
    ///
    /// When unmounting a volume, the value of this field is set to the latest
    /// transaction ID, which should match the value in [Self::modified_by].
    pub cloneinfo_xid: u64,

    /// The object identifier of the extended snapshot metadata object (`apfs_snap_meta_ext_oid`).
    ///
    /// Added in macOS 10.15.
    pub snapshot_metadata_ext_oid: VirtualObjectIdentifierRaw,

    /// The volume group the volume belongs to (`apfs_volume_group_id`).
    ///
    /// 0 if the volume is not part of a volume group.
    ///
    /// If part of a volume group, [VolumeOptionalFeatureFlagsRaw::VolumeGroupSystemInodeSpace]
    /// should be set.
    ///
    /// Added in macOS 10.15.
    pub volume_group_id: UuidRaw,

    /// The object identifier of the integrity metadata object (`apfs_integrity_meta_oid`).
    ///
    /// If non-0, [VolumeIncompatibleFeatureFlagsRaw::SealedVolume] should also be set.
    ///
    /// Added in macOS 11.0
    pub integrity_meta_oid: VirtualObjectIdentifierRaw,

    /// The object identifier of the file extent tree (`apfs_fext_tree_oid`).
    ///
    /// If non-0, [VolumeIncompatibleFeatureFlagsRaw::SealedVolume] should also be set.
    ///
    /// Added in macOS 11.0
    pub file_extent_tree_oid: VirtualObjectIdentifierRaw,

    /// The type of the file extent tree (`apfs_fext_tree_type`).
    ///
    /// Typically a physical object pointing to a B-tree root node with
    /// a subtype of [ObjectType::FileExtentsBTree].
    ///
    /// Added in macOS 11.0.
    pub file_extent_tree_type: ObjectTypeValueRaw,

    /// Reserved (`reserved_type`).
    pub reserved_type: ObjectTypeValueRaw,

    /// Reserved (`reserved_oid`).
    pub reserved_oid: ObjectIdentifierRaw,
}
