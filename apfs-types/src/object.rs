// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Object types.

use crate::common::{ObjectIdentifierRaw, TransactionIdentifierRaw};
use bitflags::bitflags;
use core::fmt::Debug;
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::{
    btree::*, common::*, container::*, data_stream::*, efi_jumpstart::*, encryption::*,
    encryption_rolling::*, filesystem::*, fusion::*, object_map::*, reaper::*, snapshot::*,
    snapshot::*, space_manager::*, volume::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum ObjectType {
    /// As a type, an invalid object; as a subtype, an object with no subtype (`OBJECT_TYPE_INVALID`).
    Invalid = 0,
    /// A container superblock (`OBJECT_TYPE_NX_SUPERBLOCK`).
    ///
    /// Values are [ContainerSuperblockRaw].
    ContainerSuperblock = 1,

    /// A B-tree root node (`OBJECT_TYPE_BTREE`).
    ///
    /// Values are [BTreeNodeRaw].
    BTreeRoot = 2,

    /// A B-tree node (`OBJECT_TYPE_BTREE_NODE`).
    ///
    /// Values are [BTreeNodeRaw].
    BTreeNode = 3,

    /// A space manager (`OBJECT_TYPE_SPACEMAN`).
    ///
    /// Values are [SpaceManagerBlockRaw].
    SpaceManagerHeader = 5,

    /// A chunk-info address block used by the space manager (`OBJECT_TYPE_SPACEMAN_CAB`).
    ///
    /// Values are [ChunkInfoAddressesBlockRaw].
    SpaceManagerChunkInformationAddressBlock = 6,

    /// A chunk-info block used by the space manager (`OBJECT_TYPE_SPACEMAN_CIB`).
    ///
    /// Values are [ChunkInfoBlockRaw].
    SpaceManagerChunkInformationBlock = 7,

    /// A free-space bitmap used by the space manager (`OBJECT_TYPE_SPACEMAN_BITMAP`).
    SpaceManagerBitmap = 8,

    /// A free-space queue used by the space manager (`OBJECT_TYPE_SPACEMAN_FREE_QUEUE`).
    SpaceManagerFreeQueue = 9,

    /// An extents-list tree (`OBJECT_TYPE_EXTENT_LIST_TREE`).
    ///
    /// A mapping from [PhysicalAddressRaw] to [PhysicalAddressRangeRaw].
    ExtentListTree = 10,

    /// Object map (`OBJECT_TYPE_OMAP`).
    ///
    /// As a type, an [ObjectMapBlockRaw].
    /// As a subtype, a tree that stores the records of an object map.
    ObjectMap = 11,

    /// A checkpoint map (`OBJECT_TYPE_CHECKPOINT_MAP`).
    ///
    /// Values are [CheckpointMapBlockRaw].
    CheckpointMap = 12,

    /// A volume (`OBJECT_TYPE_FS`).
    ///
    /// Values are [VolumeSuperblockRaw].
    VolumeSuperblock = 13,

    /// A tree containing file-system records (`OBJECT_TYPE_FSTREE`).
    ///
    /// This type is used only as a subtype of a tree.
    ///
    /// The keys and values stored in the tree vary. Each key begins with [FileSystemKeyRaw],
    /// which contains a field that indicates the type of that key and its value.
    FilesystemTree = 14,

    /// A tree containing extent references (`OBJECT_TYPE_BLOCKREFTREE`).
    ///
    /// A mapping from [PhysicalExtentRecordKeyRaw] to [PhysicalExtentRecordValueRaw].
    ExtentReferenceTree = 15,

    /// A tree containing snapshot metadata for a volume (`OBJECT_TYPE_SNAPMETATREE`).
    ///
    /// A mapping from [SnapshotMetadataRecordKeyRaw] to [SnapshotMetadataRecordValueRaw].
    SnapshotMetadataTree = 16,

    /// A reaper (`OBJECT_TYPE_NX_REAPER`).
    ///
    /// Values are [ReaperBlockRaw].
    Reaper = 17,

    /// A reap list (`OBJECT_TYPE_NX_REAP_LIST`).
    ///
    /// Values are [ReapListBlockRaw].
    ReaperList = 18,

    /// A tree containing information about snapshots of an object map (`OBJECT_TYPE_OMAP_SNAPSHOT`).
    ///
    /// (A mapping from [TransactionIdentifierRaw] to [ObjectMapSnapshotRaw].
    ObjectMapSnapshot = 19,

    /// EFI information used for booting (`OBJECT_TYPE_EFI_JUMPSTART`).
    ///
    /// Value is an [EfiJumpstartBlockRaw].
    EfiJumpstart = 20,

    /// A tree used for Fusion devices to track blocks from the hard drive that are cached on the solid-state drive (`OBJECT_TYPE_FUSION_MIDDLE_TREE`).
    ///
    /// A mapping from [FusionMiddleTreeKey] to [FusionMiddleTreeValueRaw].
    FusionMiddleTree = 21,

    /// A write-back cache state used for Fusion devices (`OBJECT_TYPE_NX_FUSION_WBC`).
    ///
    /// Values are [FusionWritebackCacheBlockRaw].
    FusionWritebackCache = 22,

    /// A write-back cache list used for Fusion devices (`OBJECT_TYPE_NX_FUSION_WBC_LIST`).
    ///
    /// Values are [FusionWritebackCacheListBlockRaw].
    FusionWritebackCacheList = 23,

    /// An encryption-rolling state (`OBJECT_TYPE_ER_STATE`).
    ///
    /// Values are [EncryptionRollingStateBlockRaw].
    EncryptionRollingState = 24,

    /// A general-purpose bitmap (`OBJECT_TYPE_GBITMAP`).
    ///
    /// Values are [GeneralPurposeBitmapRaw].
    GeneralPurposeBitmap = 25,

    /// A B-tree of general-purpose bitmaps (a mapping from uint64_t to uint64_t) (`OBJECT_TYPE_GBITMAP_TREE`).
    GeneralPurposeBitmapBTree = 26,

    /// A block containing a general-purpose bitmap (`OBJECT_TYPE_GBITMAP_BLOCK`).
    ///
    /// Values are [GeneralPurposeBitmapBlockRaw].
    GeneralPurposeBitmapBlock = 27,

    /// Information that can be used to recover from a system crash if one occurs during the encryption rolling process (`OBJECT_TYPE_ER_RECOVERY_BLOCK`).
    ///
    /// Values are [EncryptionRollingRecoveryBlockRaw].
    EncryptionRollingRecoveryBlock = 28,

    /// Additional metadata about snapshots (snap_meta_ext_obj_phys_t.) (`OBJECT_TYPE_SNAP_META_EXT`)
    SnapshotMetadata = 29,

    /// An integrity metadata object (integrity_meta_phys_t) (`OBJECT_TYPE_INTEGRITY_META`).
    IntegrityMetadata = 30,

    /// A B-tree of file extents (`OBJECT_TYPE_FEXT_TREE`).
    ///
    /// A mapping from [FileExtentRecordKeyRaw] to [FileExtentRecordValueRaw].
    FileExtentsBTree = 31,

    /// Reserved (`OBJECT_TYPE_RESERVED_20`).
    Reserved20 = 0x20,

    /// Reserved for testing (`OBJECT_TYPE_TEST`).
    Test = 0xff,

    /// A container's keybag (`OBJECT_TYPE_CONTAINER_KEYBAG`).
    ///
    /// Value is a [MediaKeybagRaw].
    ContainerKeybag = 0x6b657973, // "keys"

    /// A volume's keybag (`OBJECT_TYPE_VOLUME_KEYBAG`).
    ///
    /// Value is a [MediaKeybagRaw].
    VolumeKeybag = 0x72656373, // "recs"

    /// A media keybag (`OBJECT_TYPE_MEDIA_KEYBAG`).
    ///
    /// Value is a [MediaKeybagRaw].
    MediaKeybag = 0x6d6b6579, // "mkey"

    #[num_enum(catch_all)]
    Unknown(u32),
}

/// Represents the storage backend for an object.
pub enum StorageClass {
    /// Physical storage.
    Physical,
    /// Ephemeral storage.
    Ephemeral,
    /// Virtual storage.
    Virtual,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ObjectTypeFlags: u32 {
         /// A virtual object (`OBJ_VIRTUAL`).
        const Virtual = 0x0;

        /// An ephemeral object (`OBJ_EPHEMERAL`).
        const Ephemeral = 0x80000000;

        /// A physical object (`OBJ_PHYSICAL`).
        const Physical = 0x40000000;

        /// An object stored without an [ObjectHeaderRaw] header (`OBJ_NOHEADER`).
        const NoHeader = 0x20000000;

        /// An encrypted object (`OBJ_ENCRYPTED`).
        const Encrypted = 0x10000000;

        /// An ephemeral object that isn't persisted across unmounting (`OBJ_NONPERSISTENT`).
        const NoPersistent = 0x08000000;

        const _ = !0;
    }
}

impl ObjectTypeFlags {
    /// Obtain the enumerated storage class for this object.
    pub fn storage_class(&self) -> StorageClass {
        if self.contains(Self::Ephemeral) {
            StorageClass::Ephemeral
        } else if self.contains(Self::Physical) {
            StorageClass::Physical
        } else {
            StorageClass::Virtual
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectTypeValueRaw(pub u32);

impl Debug for ObjectTypeValueRaw {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectTypeValue")
            .field("type", &self.object_type())
            .field(
                "flags",
                &ObjectTypeFlags::from_bits_retain(self.flags_raw()),
            )
            .finish()
    }
}

impl ObjectTypeValueRaw {
    /// Obtain the integer value of the object type.
    pub fn object_type_raw(&self) -> u32 {
        self.0 & 0x0000ffff
    }

    pub fn object_type(&self) -> ObjectType {
        ObjectType::from_primitive(self.object_type_raw())
    }

    /// Obtain the integer value of the object flags.
    pub fn flags_raw(&self) -> u32 {
        self.0 & 0xffff0000
    }

    pub fn flags(&self) -> ObjectTypeFlags {
        ObjectTypeFlags::from_bits_retain(self.flags_raw())
    }
}

/// Common object header (`obj_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectHeaderRaw {
    pub checksum: u64,
    pub identifier: ObjectIdentifierRaw,
    pub transaction_identifier: TransactionIdentifierRaw,
    pub typ: ObjectTypeValueRaw,
    pub subtype: ObjectTypeValueRaw,
}
