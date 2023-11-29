// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Container level primitives, including checkpoints.

use crate::{
    common::{
        EphemeralObjectIdentifierRaw, ObjectIdentifierRaw, PhysicalAddressRangeRaw,
        PhysicalAddressRaw, PhysicalObjectIdentifierRaw, TransactionIdentifierRaw, UuidRaw,
        VirtualObjectIdentifierRaw,
    },
    object::{ObjectHeaderRaw, ObjectTypeValueRaw},
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::Range;

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

#[cfg(doc)]
use crate::{efi_jumpstart::*, encryption::*, fusion::*, object::*, space_manager::*};

/// Magic value in container superblock (`NX_MAGIC`).
pub const CONTAINER_SUPERBLOCK_MAGIC: &[u8; 4] = b"NXSB";

/// The maximum number of file systems that a container can define (`NX_MAX_FILE_SYSTEMS`).
pub const CONTAINER_MAX_FILE_SYSTEMS: usize = 100;

/// Number of entries in [ContainerSuperblockRaw::ephemeral_info] array (`NX_EPH_INFO_COUNT`).
pub const CONTAINER_EPHEMERAL_INFO_COUNT: usize = 4;

/// Minimum size in blocks for structures that contain ephemeral data (`NX_EPH_MIN_BLOCK_COUNT`).
///
/// Used as part of choosing the size for a container's checkpoint data area.
pub const CONTAINER_EPHEMERAL_DATA_MINIMUM_BLOCK_COUNT: usize = 8;

/// The number of structures that contain ephemeral data that a volume can have (`NX_MAX_FILE_SYSTEM_EPH_STRUCTS`).
///
/// Used as part of choosing the size for a container's checkpoint data area.
pub const CONTAINER_MAX_FILE_SYSTEM_EPHEMERAL_DATA_STRUCTS: usize = 4;

/// Minimum number of checkpoints that can fit in checkpoint data (`NX_TX_MIN_CHECKPOINT_COUNT`).
///
/// Used as part of choosing the size for a container's checkpoint data area.
pub const CONTAINER_MINIMUM_CHECKPOINT_COUNT: usize = 4;

/// The version number for structures that contain ephemeral data (`NX_EPH_INFO_VERSION_1`).
pub const CONTAINER_EPHEMERAL_INFO_VERSION: u64 = 1;

/// Smallest supported container block size (`NX_MINIMUM_BLOCK_SIZE`).
pub const CONTAINER_MINIMUM_BLOCK_SIZE_BYTES: u32 = 4096;

/// Default container block size (`NX_DEFAULT_BLOCK_SIZE`).
pub const CONTAINER_DEFAULT_BLOCK_SIZE_BYTES: u32 = 4096;

/// Largest supported container block size (`NX_MAXIMUM_BLOCK_SIZE`).
///
/// Restricted in size due to use of u16 in some data structures.
pub const CONTAINER_MAXIMUM_BLOCK_SIZE_BYTES: u32 = 65536;

/// Minimum allowed size of a container in bytes (`NX_MINIMUM_CONTAINER_SIZE`).
pub const MINIMUM_CONTAINER_SIZE_BYTES: u64 = 1048576;

/// Partition type for a partition containing an Apple file system container.
pub const APFS_GPT_PARTITION_UUID: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";

bitflags! {
    /// Container flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct ContainerFlagsRaw: u64 {
        /// Reserved (`NX_RESERVED_1`).
        ///
        /// Preserve if set.
        const Reserved1 = 0x01;
        /// Reserved (`NX_RESERVED_2`).
        ///
        /// Preserve during reading, unset during modification.
        const Reserved2 = 0x02;
        /// The container uses software cryptography (`NX_CRYPTO_SW`);
        ///
        /// If set, [FileExtentRecordValue::cryptography_id] should be
        /// [SOFTWARE_CRYPTOGRAPHY_ID].
        const SoftwareCryptography = 0x04;

        const _ = !0;
    }
}

bitflags! {
    /// Optional container feature flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct ContainerCompatibleFeaturesRaw: u64 {
        /// Volumes support defragmentation (`NX_FEATURE_DEFRAG`).
        const Defragmentation = 0x01;
        /// Using low capacity fusion drive mode (`NX_FEATURE_LCFD`).
        const LowCapacityFusionDrive = 0x02;

        const _ = !0;
    }
}

bitflags! {
    /// Container feature flags where missing support results in read-only containers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct ContainerReadonlyCompatibleFeaturesRaw: u64 {
        const _ = !0;
    }
}

bitflags! {
    /// Backward incompatible feature flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct ContainerIncompatibileFeaturesRaw: u64 {
        /// Container uses version 1 of the Apple File System (`NX_INCOMPAT_VERSION1`).
        ///
        /// Version 1 was only implemented in macOS 10.12. It probably doesn't
        /// exist in the wild.
        const Version1 = 0x01;

        /// Container uses version 2 of the Apple File System (`NX_INCOMPAT_VERSION2`).
        ///
        /// This version was implemented in macOS 10.13 and iOS 10.3.
        const Version2 = 0x02;

        /// The container supports fusion drives (`NX_INCOMPAT_FUSION`).
        const FusionDrives = 0x100;

        /// A bit mask of known backwards incompatible features (`NX_SUPPORTED_INCOMPAT_MASK`).
        const BackwardsIncompatible = ContainerIncompatibileFeaturesRaw::Version2.bits() | ContainerIncompatibileFeaturesRaw::FusionDrives.bits();

        const _ = !0;
    }
}

/// Indexes into a container's counters (`nx_counter_id_t`).
#[repr(usize)]
pub enum ContainerCounterIndex {
    /// Number of times a checksum has been computed while writing objects (`NX_CNTR_OBJ_CKSUM_SET`).
    Set = 0,

    /// Number of times an object's checksum was invalid when reading (`NX_CNTR_OBJ_CKSUM_FAIL`).
    Fail = 1,
}

/// The maximum number of counters (`NX_NUM_COUNTERS`).
pub const CONTAINER_COUNTERS_COUNT: usize = 32;

/// A container superblock (`nx_superblock_t`).
///
/// Main data structure for an APFS container. This data structure contains
/// high-level metadata about the container and tells you where the main data
/// structures are inside the byte addressable entity holding the file system.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ContainerSuperblockRaw {
    /// Object header (`nx_o`).
    ///
    /// Type should be [ObjectType::ContainerSuperblock]
    /// and subtype should be [ObjectType::Invalid].
    pub object: ObjectHeaderRaw,

    /// Magic value further indicating this is a superblock (`nx_magic`).
    ///
    /// Value is [CONTAINER_SUPERBLOCK_MAGIC].
    pub magic: [u8; 4],

    /// The logical block size used in the Apple File System container (`nx_block_size`).
    ///
    /// Value must be between [CONTAINER_MINIMUM_BLOCK_SIZE_BYTES] and
    /// [CONTAINER_MAXIMUM_BLOCK_SIZE_BYTES], inclusive.
    pub block_size_bytes: u32,

    /// The total number of logical blocks in the container (`nx_block_count`).
    pub block_count: u64,

    /// A bit field of the optional features being used by this container (`nx_features`).
    ///
    /// It is supposed to be safe for implementations to be able to mount volumes from
    /// this container with unknown or unsupported flags in this field.
    pub compatible_features: ContainerCompatibleFeaturesRaw,

    /// A bit field of the read-only compatible features being used by this container (`nx_readonly_compatible_features`).
    ///
    /// If an implementation doesn't support flags in this field, it should mount volumes
    /// from this container as read-only.
    ///
    /// No flags are currently known and no type to represent them has been assigned.
    pub readonly_compatible_features: ContainerReadonlyCompatibleFeaturesRaw,

    /// A bit field of the backward-incompatible features being used by this container (`nx_incompatible_features`).
    ///
    /// If an implementation doesn't support flags in this field, it should not mount
    /// volumes from this container.
    pub incompatible_features: ContainerIncompatibileFeaturesRaw,

    /// Container identifier (UUID) (`nx_uuid`).
    pub identifier: UuidRaw,

    /// The next object identifier to be used for a new ephemeral or virtual object (`nx_next_oid`).
    pub next_object_identifier: ObjectIdentifierRaw,

    /// The next transaction identifier to be used (`nx_next_xid`).
    pub next_transaction_identifier: TransactionIdentifierRaw,

    /// The number of blocks used by the checkpoint descriptor area (`nx_xp_desc_blocks`).
    ///
    /// The highest bit is used as a flag as described by
    /// [Self::checkpoint_descriptor_area_block_number].
    pub checkpoint_descriptor_area_block_count: u32,

    /// The number of blocks used by the checkpoint data area (`nx_xp_data_blocks`).
    ///
    /// The highest bit is used as a flag as described by
    /// [Self::checkpoint_data_area_block_number].
    pub checkpoint_data_area_block_count: u32,

    /// Either the base address of the checkpoint descriptor area or the physical object identifier of a tree that contains the address information (`nx_xp_desc_base`).
    ///
    /// If the highest bit of [Self::checkpoint_descriptor_area_block_count] is 0,
    /// the checkpoint descriptor area is stored as contiguous physical blocks
    /// starting at the value specified.
    ///
    /// Otherwise, this field contains the physical object identifier of a B-tree.
    /// The tree's keys are block offsets into the checkpoint descriptor area.
    /// The tree's values are instances of [PhysicalAddressRangeRaw] that contain the
    /// fragment's location and size.
    pub checkpoint_descriptor_area_block_number: PhysicalAddressRaw,

    /// Either the base address of the checkpoint data area or the physical object identifier of a tree that contains the address information (`nx_xp_data_base`).
    ///
    /// Similar behavior to [Self::checkpoint_descriptor_area_block_number] except
    /// the checkpoint data area is being described.
    pub checkpoint_data_area_block_number: PhysicalAddressRaw,

    /// The next index to use in the checkpoint descriptor area (`nx_xp_desc_next`).
    ///
    /// If this structure is part of a checkpoint, this field should have a non-0 value.
    /// If not, ignore this field when reading and set to 0 for new instances.
    pub checkpoint_descriptor_area_next_available_index: u32,

    /// The next index to use in the checkpoint data area (`nx_xp_data_next`).
    ///
    /// Similar semantics to [Self::checkpoint_descriptor_area_next_available_index].
    pub checkpoint_data_area_next_available_index: u32,

    /// The index of the first valid item in the checkpoint descriptor area (`nx_xp_desc_index`).
    ///
    /// Similar semantics to [Self::checkpoint_descriptor_area_next_available_index].
    pub checkpoint_descriptor_area_start_index: u32,

    /// The number of blocks in the checkpoint descriptor area (`nx_xp_desc_len`).
    ///
    /// Similar semantics to [Self::checkpoint_descriptor_area_next_available_index].
    pub checkpoint_descriptor_area_length: u32,

    /// The index of the first valid item in the checkpoint data area (`nx_xp_data_index`).
    ///
    /// Similar semantics to [Self::checkpoint_descriptor_area_next_available_index].
    pub checkpoint_data_area_start_index: u32,

    /// The number of blocks in the checkpoint data area (`nx_xp_data_len`).
    ///
    /// Similar semantics to [Self::checkpoint_descriptor_area_next_available_index].
    pub checkpoint_data_area_length: u32,

    /// The object identifier for the space manager (`nx_spaceman_oid`).
    pub space_manager_oid: EphemeralObjectIdentifierRaw,

    /// The object identifier for the container's object map (`nx_omap_oid`).
    pub object_map_block_number: PhysicalObjectIdentifierRaw,

    /// The object identifier for the reaper (`nx_reaper_oid`).
    pub reaper_oid: EphemeralObjectIdentifierRaw,

    /// Reserved for testing (`nx_test_type`).
    ///
    /// Value should always be 0 on disk.
    ///
    /// Field isn't reserved by Apple and implementations can use it for testing.
    pub testing_type: u32,

    /// The maximum number of volumes that can be stored in this container (`nx_max_file_systems`).
    ///
    /// This value is calculated by dividing the size of the container by 512 MiB and rounding up.
    ///
    /// Value cannot be larger than [CONTAINER_MAX_FILE_SYSTEMS].
    pub maximum_filesystems: u32,

    /// An array of object identifiers for volumes (`nx_fs_oid`).
    ///
    /// The referenced objects are [ObjectType::BTreeRoot] with subtype
    /// [ObjectType::FilesystemTree].
    pub volume_oids: [VirtualObjectIdentifierRaw; CONTAINER_MAX_FILE_SYSTEMS],

    /// An array of counters that store information about the container (`nx_counters`).
    ///
    /// Indexes are defined by [ContainerCounterIndex].
    pub counters: [u64; CONTAINER_COUNTERS_COUNT],

    /// The physical range of blocks where space will not be allocated (`nx_blocked_out_prange`).
    ///
    /// Used alongside [Self::evict_mapping_tree_oid] when shrinking a partition. If nothing
    /// is blocked out, the block count should be 0 and the address is ignored.
    pub blocked_out_prange: PhysicalAddressRangeRaw,

    /// The object identifier of a tree used to keep track of objects that must be moved out of blocked-out storage (`nx_evict_mapping_tree_oid`).
    ///
    /// Keys in the tree are physical addresses of blocks that must be moved.
    /// Values in the tree are [EvictMappingValueRaw] describing where blocks are moving
    /// to.
    ///
    /// This identifier is only valid when shrinking a partition.
    pub evict_mapping_tree_oid: PhysicalObjectIdentifierRaw,

    /// Other container flags (`nx_flags`).
    pub flags: ContainerFlagsRaw,

    /// The physical object identifier of the object that contains EFI driver data extents (`nx_efi_jumpstart`).
    ///
    /// The referenced object is a [EfiJumpstartBlockRaw].
    pub efi_jumpstart: PhysicalAddressRaw,

    /// The ID of the container's Fusion set (`nx_fusion_uuid`).
    ///
    /// The HD and SSD each have a partition combining to form a single container.
    /// Each partition has its own [ContainerSuperblockRaw] at block 0 and each value
    /// has the same lower 127 bits in this field. The highest bit is set for the
    /// fusion set's main device and 0 for the other device.
    ///
    /// 0s for non-Fusion containers.
    pub fusion_set_identifier: UuidRaw,

    /// The location of the container's keybag (`nx_keylocker`).
    ///
    /// Data is an instance of [MediaKeybagRaw].
    pub key_bag: PhysicalAddressRangeRaw,

    /// An array of fields used in the management of ephemeral data (`nx_ephemeral_info`).
    ///
    /// The first entry records how the checkpoint data area size was chosen using the
    /// following formula:
    ///
    /// ```text
    /// (min_block_count << 32)
    /// | ((CONTAINER_MAX_FILE_SYSTEM_EPHEMERAL_DATA_STRUCTS & 0xffff) << 16)
    /// | CONTAINER_EPHEMERAL_INFO_VERSION
    /// ```
    ///
    /// `min_block_count` is dependent on the size of the container.
    ///
    /// If >128 MiB, [CONTAINER_EPHEMERAL_DATA_MINIMUM_BLOCK_COUNT] is used.
    /// Else, the value is taken from the [SpaceManagerBlockRaw::free_queue]'s
    /// `MAIN` entry's (array offset 1) [SpaceManagerFreeQueueRaw::tree_node_limit]
    /// value from the space referenced by this struct's [Self::space_manager_oid] field.
    pub ephemeral_info: [u64; CONTAINER_EPHEMERAL_INFO_COUNT],

    /// Reserved for testing (`nx_test_oid`).
    ///
    /// Only set to 0 on disk.
    ///
    /// Not reserved and implementations can store an identifier during testing.
    pub test_identifier: ObjectIdentifierRaw,

    /// The object identifier of the Fusion middle tree (`nx_fusion_mt_oid`).
    ///
    /// Set to 0 for non-Fusion drives.
    ///
    /// Object is a B-tree mapping [FusionMiddleTreeKey] to [FusionMiddleTreeValueRaw].
    ///
    /// (a B-tree mapping fusion_mt_key_t to fusion_mt_val_t), or zero if for non-Fusion drives ().
    pub fusion_middle_tree_block_number: PhysicalObjectIdentifierRaw,

    /// The object identifier of the Fusion write-back cache state (`nx_fusion_wbc_oid`).
    ///
    /// Object is a [FusionWritebackCacheBlockRaw].
    ///
    /// Value is 0 for a non-Fusion drive.
    pub fusion_writeback_cache_identifier: EphemeralObjectIdentifierRaw,

    /// The blocks used for the Fusion write-back cache area (`nx_fusion_wbc`).
    ///
    /// 0 for non-Fusion drives.
    pub fusion_writeback_cache: PhysicalAddressRangeRaw,

    /// Reserved (`nx_newest_mounted_version`).
    ///
    /// Apple's implementation uses to record the newest version of the software
    /// that mounted the container. Other implementations should not modify this
    /// field.
    ///
    /// This integer can be interpreted as a fixed point decimal number.
    pub newest_mounted_version: u64,

    /// Wrapped media key (`nx_mkb_locker`).
    pub mkb_locker: PhysicalAddressRangeRaw,
}

/// A mapping from an ephemeral object identifier to its physical address in the checkpoint data area (`checkpoint_mapping_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct CheckpointMappingRaw {
    /// The object's type (`cpm_type`).
    pub object_type: ObjectTypeValueRaw,
    /// The object's subtype (`cpm_subtype`).
    pub object_subtype: ObjectTypeValueRaw,
    /// The size, in bytes, of the object (`cpm_size`).
    pub size: u32,
    /// Reserved (`cpm_pad`)
    pub padding: u32,
    /// The object identifier of the volume that the object is associated with (`cpm_fs_oid`).
    pub filesystem_identifier: VirtualObjectIdentifierRaw,
    /// The object identifier (`cpm_oid`).
    pub container_identifier: EphemeralObjectIdentifierRaw,
    /// The address in the checkpoint data area where the object is stored (`cpm_paddr`).
    pub address: PhysicalAddressRaw,
}

bitflags! {
    /// Flags for [CheckpointMapBlockRaw].
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct CheckpointFlagsRaw: u32 {
        /// Last checkpoint map object.
        const Last = 0x01;

        const _ = !0;
    }
}

/// A checkpoint-mapping block (`checkpoint_map_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct CheckpointMapBlockRaw {
    pub object: ObjectHeaderRaw,
    /// A bit field that contains additional information about the list of checkpoint mappings
    pub flags: CheckpointFlagsRaw,
    /// The number of checkpoint mappings in the array
    pub count: u32,
    /// The checkpoing mappings.
    #[cfg_attr(
        feature = "derive",
        apfs(
            trailing_data = "crate::pod::MemoryBackedArray<CheckpointMappingRaw, CheckpointMappingParsed>"
        )
    )]
    pub map: [CheckpointMappingRaw; 0],
}

impl DynamicSized for CheckpointMapBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        let size = self.count as usize * core::mem::size_of::<CheckpointMappingRaw>();

        0..size
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for CheckpointMapBlockRaw {
    type TrailingData =
        crate::pod::MemoryBackedArray<CheckpointMappingRaw, CheckpointMappingParsed>;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::MemoryBackedArray::new(data, self.count as _)
    }
}

/// A range of physical addresses that data is being moved to (`evict_mapping_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct EvictMappingValueRaw {
    /// Address for start of destination (`dst_paddr`).
    pub destination_address: PhysicalAddressRaw,
    /// The number of blocks being moved (`len`).
    pub block_count: u64,
}
