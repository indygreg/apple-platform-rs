// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Filesystem objects.

use crate::{common::TimeRaw, DynamicSized};
use bitflags::bitflags;
use core::cmp::Ordering;
use core::fmt::{Debug, Formatter};
use core::ops::{Range, RangeFrom};
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

#[cfg(doc)]
use crate::{
    common::*, data_stream::*, encryption::*, filesystem_extended_fields::*, object::*,
    sealed_volume::*, sibling::*, snapshot::*,
};

/// The type of a filesystem record (`j_obj_types`).
///
/// This value is stored in the type bits of a [FileSystemKeyRaw::obj_id_and_type].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum FileSystemObjectType {
    /// A record of any type (`APFS_TYPE_ANY`).
    ///
    /// This enumeration case is used only in search queries and in tests
    /// when iterating over objects. It's not valid as the type
    /// of a file-system object.
    Any = 0,

    /// Metadata about a snapshot (`APFS_TYPE_SNAP_METADATA`).
    ///
    /// Keys are [SnapshotMetadataRecordKeyRaw] and values are
    /// [SnapshotMetadataRecordValueRaw].
    SnapshotMetadata = 1,

    /// A physical extent record (`APFS_TYPE_EXTENT`).
    ///
    /// Keys are [PhysicalExtentRecordKeyRaw] and values are
    /// [PhysicalExtentRecordValueRaw].
    Extent = 2,

    /// An inode (`APFS_TYPE_INODE`).
    ///
    /// Keys are [InodeRecordKeyRaw] and values are [InodeRecordValueRaw].
    Inode = 3,

    /// An extended attribute (`APFS_TYPE_XATTR`).
    ///
    /// Keys are [ExtendedAttributeRecordKeyRaw] and values are
    /// [ExtendedAttributeRecordValueRaw].
    ExtendedAttribute = 4,

    /// A mapping from an inode to hard links that the inode is the target of (`APFS_TYPE_SIBLING_LINK`).
    ///
    /// Keys are [SiblingLinkRecordKeyRaw] and values are
    /// [SiblingLinkRecordValueRaw].
    SiblinkLink = 5,

    /// A data stream (`APFS_TYPE_DSTREAM_ID`).
    ///
    /// Keys are [DataStreamIdRecordKeyRaw] and values are [DataStreamIdRecordValueRaw].
    DataStreamId = 6,

    /// A per-file encryption state (`APFS_TYPE_CRYPTO_STATE`).
    ///
    /// Keys are [EncryptionStateRecordKeyRaw] and values are
    /// [EncryptionStateRecordValueRaw].
    EncryptionState = 7,

    /// A physical extent record for a file (`APFS_TYPE_FILE_EXTENT`).
    ///
    /// Keys are [FileExtentRecordKeyRaw] and values are
    /// [FileExtentRecordValueRaw].
    FileExtent = 8,

    /// A directory entry (`APFS_TYPE_DIR_REC`).
    ///
    /// Keys are [DirectoryEntryRecordKeyRaw] and values are
    /// [DirectoryEntryRecordValueRaw].
    DirectoryRecord = 9,

    /// Information about a directory (`APFS_TYPE_DIR_STATS`).
    ///
    /// Keys are [DirectoryInformationRecordKeyRaw] and values are
    /// [DirectoryInformationRecordValueRaw].
    DirectoryStats = 10,

    /// The name of a snapshot (`APFS_TYPE_SNAP_NAME`).
    ///
    /// Keys are [SnapshotNameRecordKeyRaw] and values are
    /// [SnapshotNameRecordValueRaw].
    SnapshotName = 11,

    /// A mapping from a hard link to its target inode (`APFS_TYPE_SIBLING_MAP`).
    ///
    /// Keys are [SiblingMapRecordKeyRaw] and values are
    /// [SiblingMapRecordValueRaw].
    SiblingMap = 12,

    /// Additional information about file data (`APFS_TYPE_FILE_INFO`).
    ///
    /// Keys are [FileInfoRecordKeyRaw] and values are [FileInfoRecordValueRaw].
    FileInfo = 13,

    /// An invalid object type (`APFS_TYPE_INVALID`)
    Invalid = 15,

    #[num_enum(catch_all)]
    Unknown(u8),
}

/// An invalid inode number (`INVALID_INO_NUM`).
pub const INODE_INVALID: u64 = 0;

/// Inode number for the root directory's parent (`ROOT_DIR_PARENT`).
///
/// Sentinel only value: should never occur on an inode.
pub const INODE_ROOT_DIRECTORY_PARENT: u64 = 1;

/// Inode number for the root directory of the volume (`ROOT_DIR_INO_NUM`).
pub const INODE_ROOT_DIRECTORY: u64 = 2;

/// Inode number for the private directory (`PRIV_DIR_INO_NUM`).
///
/// The private directory's filename is `private-dir`.
///
/// When creating a new volume, you must create a directory with this
/// name and inode number.
///
/// The directory isn't reserved by Apple. Implementations can use it to
/// record their own state. But they should ensure they only modify their own
/// records in this directory.
pub const INODE_PRIVATE_DIRECTORY: u64 = 3;

/// The inode number for the directory where snapshot metadata is stored (`SNAP_DIR_INO_NUM`)
///
/// Snapshot inodes are stored in the snapshot metadata tree.
pub const INODE_SNAPSHOT_METADATA: u64 = 6;

/// The inode used for storing references to purgeable files (`PURGEABLE_DIR_INO_NUM`)
///
/// This inode number and directory records that use it are reserved.
/// Implementations should not modify them.
pub const INODE_PURGEABLE_DIRECTORY: u64 = 7;

/// The smallest inode number available for user content (`MIN_USER_INO_NUM`).
///
/// Values less than this are reserved.
pub const INODE_MINIMUM_USER: u64 = 16;

/// The smallest inode number used by the system volume in a volume group (`UNIFIED_ID_SPACE_MARK`).
pub const INODE_UNIFIED_ID_SPACE_MARK: u64 = 0x0800000000000000;

bitflags! {
    /// The flags used by inodes (`j_inode_flags`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u64))]
    pub struct InodeFlagsRaw: u64 {
        /// Used internally by Apple's implementation (`INODE_IS_APFS_PRIVATE`).
        ///
        /// Inodes with this flag aren't considered part of the volume.
        ///
        /// They can't be cloned, renamed, or deleted.
        ///
        /// They aren't considered when counting files. They are also
        /// hidden from end-users.
        ///
        /// Implementations can use this flag for their own record keeping. However,
        /// implementations should take care to only modify their own inodes using
        /// this flag.
        ///
        /// Apple's implementation uses this flag for temporary files.
        const IsApfsPrivate = 0x01;

        /// The inode tracks the size of all its children (`INODE_MAINTAIN_DIR_STATS`).
        ///
        /// Only valid on a directory and must also be set on the directory's
        /// subdirectories.
        ///
        /// When removing, should be removed from children subdirectories unless
        /// [Self::DirStatsOrigin] is also set.
        const MaintainDirStats = 0x02;

        /// The [Self::MaintainDirStates] flag is set explicitly (`INODE_DIR_STATS_ORIGIN`).
        ///
        /// As opposed to set via inheritance.
        ///
        /// Can be set multiple times in a directory hierarchy.
        const DirStatsOrigin = 0x04;

        /// The data protection class was set explicitly (`INODE_PROT_CLASS_EXPLICIT`).
        const ProtectionClassExplicit = 0x08;

        /// The inode was created by cloning another one (`INODE_WAS_CLONED`).
        const WasCloned = 0x10;

        /// Reserved (`INODE_FLAG_UNUSED`).
        ///
        /// Leave unset when creating. Preserve when modifying.
        const FlagUnused = 0x20;

        /// The inode has an access control list (`INODE_HAS_SECURITY_EA`).
        const HasSecurityEa = 0x40;

        /// The inode was truncated (`INODE_BEING_TRUNCATED`).
        ///
        /// Used to facilitate truncation in the face of crashes.
        ///
        /// This flag is set at the beginning of truncation and cleared afterwards.
        const BeingTruncated = 0x80;

        /// The inode has a Finder info extended filed (`INODE_HAS_FINDER_INFO`).
        const HasFinderInfo = 0x100;

        /// The inode has a sparse byte count extended field (`INODE_IS_SPARSE`).
        const IsSparse = 0x200;

        /// The inode was cloned at least once (`INODE_WAS_EVER_CLONED`).
        ///
        /// If set, the blocks that store this inode might also be used by another
        /// inode.
        ///
        /// When deleting inodes with this flag, reference counts need to be checked
        /// before deallocating storage.
        ///
        /// There was a bug in the handling of this field prior to macOS 10.13.3
        /// that requires diligence when encountering this flag. See the Apple
        /// documentation for more.
        const WasEverCloned = 0x400;

        /// The inode is an over-provisioning file that has been trimmed (`INODE_ACTIVE_FILE_TRIMMED`).
        ///
        /// Used only on iOS. This allows blocks to be set aside for over-provisioning
        /// of storage.
        const ActiveFileTrimmed = 0x800;

        /// File content is always on the main storage device (`INODE_PINNED_TO_MAIN`).
        ///
        /// Only valid for Fusion containers. The main storage is an SSD.
        const PinnedToMain = 0x1000;

        /// File content is always on the secondary storage device (`INODE_PINNED_TO_TIER2`).
        ///
        /// Only valid for Fusion containers. Secondary storage is a hard drive.
        const PinnedToTier2 = 0x2000;

        /// The inode has a resource fork (`INODE_HAS_RSRC_FORK`).
        ///
        /// Exclusive with [Self::NoResourceFork].
        ///
        /// If neither set, there is no resource fork.
        const HasResourceFork = 0x4000;

        /// The inode doesn't have a resource fork (`INODE_NO_RSRC_FORK`).
        ///
        /// Exclusive with [Self::HasResourceFork].
        const NoResourceFork = 0x8000;

        /// Inode's file content has space allocated outside of the preferred storage tier (`INODE_ALLOCATION_SPILLEDOVER`).
        const AllocationSpilledOver = 0x10000;

        /// The inode is scheduled for promotion from slow storage to fast storage (`INODE_FAST_PROMOTE`).
        ///
        /// Promotion occurs on read.
        const FastPromote = 0x20000;

        /// The inode stores its uncompressed size in the inode (`INODE_HAS_UNCOMPRESSED_SIZE`).
        ///
        /// The uncompressed size is stored in the [InodeRecordValueRaw::uncompressed_size] field.
        ///
        /// Field ignored before macOS 10.15 and iOS 13.1.
        const HasUncompressedSize = 0x40000;

        /// This inode will be deleted at the next purge (`INODE_IS_PURGEABLE`).
        const IsPurgeable = 0x80000;

        /// This inode should become purgeable when its link count drops to 1 (`INODE_WANTS_TO_BE_PURGEABLE`).
        const WantsToBePurgeable = 0x100000;

        /// This inode is the root of a sync hierarchy for fileproviderd (`INODE_IS_SYNC_ROOT`).
        ///
        /// Don't add or remove but preserve existing.
        const IsSyncRoot = 0x200000;

        /// This inode is exempt from copy-on-write behavior if the data is part of a snapshot (`INODE_SNAPSHOT_COW_EXEMPTION`).
        ///
        /// Don't add or remove this flag but preserve existing.
        ///
        /// The number of files with this flag is tracked by an extended
        /// attribute.
        const SnapshotCowExemption = 0x400000;

        /// A bit mask of flags that are inherited by files and subdirectores in a directory (`INODE_INHERITED_INTERNAL_FLAGS`).
        const InheritedInternalFlags = (
            InodeFlagsRaw::MaintainDirStats.bits() |
            InodeFlagsRaw::SnapshotCowExemption.bits()
        );

        /// A bit mask of flags that are preserved when cloning (`INODE_CLONED_INTERNAL_FLAGS`).
        const ClonedInternalFlags = (
            InodeFlagsRaw::HasResourceFork.bits() |
            InodeFlagsRaw::NoResourceFork.bits() |
            InodeFlagsRaw::HasFinderInfo.bits() |
            InodeFlagsRaw::SnapshotCowExemption.bits()
        );

        /// A bit mask of flags related to Fusion drive pinning (`APFS_INODE_PINNED_MASK`).
        const PinnedMask = (
            InodeFlagsRaw::PinnedToMain.bits() |
            InodeFlagsRaw::PinnedToTier2.bits()
        );

        const _ = !0;
    }
}

/// A header used at the beginning of all file system record keys (`j_key_t`).
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct FileSystemKeyRaw {
    /// Common record header (`hdr`).
    pub obj_id_and_type: u64,

    /// Extra key data.
    ///
    /// Not present on every key. Depends on the type decoded from the above
    /// field.
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub extra: [u8; 0],
}

impl Debug for FileSystemKeyRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("FsIdAndType")
            .field(&self.id())
            .field(&self.object_type())
            .finish()
    }
}

impl Ord for FileSystemKeyRaw {
    fn cmp(&self, other: &Self) -> Ordering {
        // IDs are compared first falling back to object type on tie.
        // This ensures that all entries sharing the same ID are stored next
        // to each other.
        (self.id(), self.typ()).cmp(&(other.id(), other.typ()))
    }
}

impl PartialOrd for FileSystemKeyRaw {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// The structure itself is fixed size. However, the structure often
// appears as a prefix to other key types. To allow instances of this
// struct to be "downcasted" into these longer types, we advertise
// ourselves as dynamic sized so input bytes can be retained by parsers.1
impl DynamicSized for FileSystemKeyRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

impl FileSystemKeyRaw {
    /// The object identifier.
    pub fn id(&self) -> u64 {
        self.obj_id_and_type & 0x0fffffffffffffff
    }

    /// The object type.
    pub fn typ(&self) -> u8 {
        ((self.obj_id_and_type & 0xf000000000000000) >> 60) as u8
    }

    /// Obtain the type of the filesystem object.
    pub fn object_type(&self) -> FileSystemObjectType {
        FileSystemObjectType::from_primitive(self.typ())
    }
}

/// Inode record key (`j_inode_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct InodeRecordKeyRaw {
    /// The record's header (`hdr`).
    ///
    /// The object identifier in the header is the file-system object's identifier,
    /// or its inode number. The type in the header is always
    /// [FileSystemObjectType::Inode].
    pub header: FileSystemKeyRaw,
}

/// Directory entry file types.
///
/// Used by [DirectoryEntryRecordValueRaw::flags] to indicate a directory entry's
/// type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum DirectoryEntryFileType {
    /// An unknown directory entry (`DT_UNKNOWN`).
    Unknown = 0,
    /// A named pipe (`DT_FIFO`).
    Fifo = 1,
    /// A character-special file (`DT_CHR`).
    Character = 2,
    /// A directory (`DT_DIR`).
    Directory = 4,
    /// A block-special file (`DT_BLK`).
    Block = 6,
    /// A regular file (`DT_REG`).
    Reg = 8,
    /// A symbolic link (`DT_LNK`).
    Link = 10,
    /// A socket (`DT_SOCK`).
    Socket = 12,
    /// A whiteout (`DT_WHY`).
    Whiteout = 14,
    /// An unknown other value.
    #[num_enum(catch_all)]
    Other(u8),
}

bitflags! {
    /// A file's mode (`mode_t`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u16))]
    pub struct FileModeRaw: u16 {
        /// Executable for other.
        const S_IXOTH = 0o1;
        /// Writeable for other.
        const S_IWOTH = 0o2;
        /// Readable for other.
        const S_IROTH = 0o4;

        /// Executable for group.
        const S_IXGRP = 0o10;
        /// Writeable for group.
        const S_IWGRP = 0o20;
        /// Readable for group.
        const S_IRGRP = 0o40;

        /// Executable for owner/user.
        const S_IXUSR = 0o100;
        /// Writeable for owner/user.
        const S_IWUSR = 0o200;
        /// Readable for owner/user.
        const S_IRUSR = 0o400;

        /// Save swapped text.
        const S_ISVTX = 0x1000;
        /// Set group ID.
        const S_ISGID = 0o2000;
        /// Set user ID.
        const S_ISUID = 0o4000;

        /// A named pipe.
        const S_IFIFO = 0o10000;
        /// A character-special file.
        const S_IFCHR = 0o20000;
        /// A directory.
        const S_IFDIR = 0o40000;
        /// A block-special file.
        const S_IFBLK = 0o60000;

        /// A regular file.
        const S_IFREG = 0o100000;
        /// A symbolic link.
        const S_IFLNK = 0o120000;
        /// A socket.
        const S_IFSOCK = 0o140000;
        /// A whiteout.
        const S_IFWHT = 0o160000;

        /// A bitmask used to access the file type.
        const S_IFMT = 0o170000;
    }
}

/// Inode record value (`j_inode_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct InodeRecordValueRaw {
    /// The identifier of the file system record for the parent directory (`parent_id`).
    pub parent_id: u64,

    /// The unique identifier used by this file's data stream (`private_id`).
    ///
    /// This value appears in [PhysicalExtentRecordValueRaw::owning_fs_object_id].
    ///
    /// For inodes without data, the value of this field in the filesystem's
    /// object identifier.
    pub private_id: u64,

    /// The time that this record was created (`create_time`).
    pub create_time: TimeRaw,

    /// The time that this record was last modified (`mod_time`).
    pub modification_time: TimeRaw,

    /// The time that this record's attributes were last modified (`change_time`).
    pub change_time: TimeRaw,

    /// The time that this record was last accessed (`access_time`).
    pub access_time: TimeRaw,

    /// The inode's flags (`internal_flags`).
    pub internal_flags: InodeFlagsRaw,

    /// The number of directory entries or hard links whose target is this inode (`nchildren`).
    ///
    /// When a directory, the number of directory entries. When not a directory,
    /// is the number of hard links.
    ///
    /// Inodes with multiple hard links in this field have additional
    /// requirements:
    ///
    /// * [Self::parent_id] refers to the parent directory of the primary link.
    /// * The name field contains the name of the primary link.
    /// * The [InodeExtendedFieldType::Name] extended field contains the
    ///   name of this link.
    /// * The filesystem object includes sibling link records.
    pub number_children_or_link: i32,

    /// The default protection class for this inode (`default_protection_class`).
    ///
    /// Files in a directory having [ProtectionClass::None] use the directory's
    /// default protection class.
    pub default_protection_class: u32,

    /// A monotonically increasing counter incremented each time an inode or its data is modified (`write_generation_counter`).
    ///
    /// Can overflow and wrap to 0.
    pub write_generation_counter: u32,

    /// The inode's BSD flags (`bsd_flags`).
    ///
    /// See `chflags(2)` and the `sys/stat.h` header.
    pub bsd_flags: u32,

    /// The user identifier of the inode's owner (`owner`).
    pub owner: u32,

    /// The group identifier of the inode's group (`group`).
    pub group: u32,

    /// The file's mode (`mode`).
    pub mode: FileModeRaw,

    /// Reserved (`pad1`).
    ///
    /// Populate with 0 for new and preserve existing.
    pub pad1: u16,

    /// The size of the file without compression (`uncompressed_size`).
    ///
    /// Only set for inodes with [InodeFlagsRaw::HasUncompressedSize].
    ///
    /// Otherwise set with 0 for new nodes and preserve on modification.
    pub uncompressed_size: u64,

    /// Extended fields data (`xfields`).
    ///
    /// An [ExtendedAttributesBlobRaw].
    #[cfg_attr(
        feature = "derive",
        apfs(trailing_data = "crate::filesystem_extended_fields::InodeRecordExtendedFieldsArray")
    )]
    pub extended_fields: [u8; 0],
}

impl DynamicSized for InodeRecordValueRaw {
    // The number of extended fields is not declared in the entry. So we need
    // to consume all available bytes in the B-tree's value.
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for InodeRecordValueRaw {
    type TrailingData = crate::filesystem_extended_fields::InodeRecordExtendedFieldsArray;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        let inner = crate::filesystem_extended_fields::ExtendedFieldsArray::new(data)?;

        Ok(inner.into())
    }
}

/// The key half of a directory entry record (`j_drec_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct DirectoryEntryRecordKeyRaw {
    /// The record's header (`hdr`).
    ///
    /// The object identifier in the header is the file-system object's identifier.
    pub header: FileSystemKeyRaw,

    /// The length of the name, including the final null character (U+0000) (`name_len`).
    pub name_length: u16,

    /// The name (`name`).
    ///
    /// A null-terminated UTF-8 string.
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    pub name: [u8; 0],
}

impl DynamicSized for DirectoryEntryRecordKeyRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.name_length as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for DirectoryEntryRecordKeyRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

/// The name length and hash of a [DirectoryEntryRecordHashedKeyRaw].
///
/// Represents the value of the [DirectoryEntryRecordHashedKeyRaw::name_length_and_hash] field.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct DirectoryEntryRecordNameLengthAndHashRaw(pub u32);

impl Debug for DirectoryEntryRecordNameLengthAndHashRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DirectoryEntryRecordNameLengthAndHashRaw")
            .field(&self.name_length())
            .field(&self.hash())
            .finish()
    }
}

impl DirectoryEntryRecordNameLengthAndHashRaw {
    /// Obtain the length of the name.
    pub fn name_length(&self) -> u32 {
        self.0 & 0x000003ff
    }

    /// Obtain the hash of the name.
    pub fn hash(&self) -> u32 {
        (self.0 & 0xfffff400) >> 10
    }
}

/// Directory entry record key with a precomputed hash (`j_drec_hashed_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct DirectoryEntryRecordHashedKeyRaw {
    /// Common header (`hdr`).
    pub header: FileSystemKeyRaw,

    /// The hash and length of the name (`name_len_and_hash`).
    ///
    /// Length is the lower 10 bits.
    /// Hash is the upper 22 bits.
    ///
    /// Hash is computed doing the following:
    ///
    /// 1. Obtain the NULL-terminated UTF-8 string.
    /// 2. Normalize using canonical decomposition (NFD).
    /// 3. Obtain a NULL-terminated UTF-32 representation.
    /// 4. Compute the CRC-32C hash of this value.
    /// 5. Complement the bits of the hash.
    /// 6. Retain the lower 22 bits of the hash.
    ///
    /// Implementations can use their own CRC function.
    pub name_length_and_hash: DirectoryEntryRecordNameLengthAndHashRaw,

    /// The name (`name`).
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    pub name: [u8; 0],
}

impl DynamicSized for DirectoryEntryRecordHashedKeyRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        // Ensure alignment.
        let v = self.name_length_and_hash;
        0..v.name_length() as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for DirectoryEntryRecordHashedKeyRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

bitflags! {
    /// Directory records flags (`dir_rec_flags`).
    #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u16))]
    pub struct DirectoryRecordFlagsRaw: u16 {
        /// The bitmask used to access the type (`DREC_TYPE_MASK`).
        ///
        /// This yields a value enumerated by [DirectoryEntryFileType].
        const TypeMask = 0x000f;

        /// Reserved (`RESERVED_10`).
        const Reserved10 = 0x0010;
    }
}

impl Debug for DirectoryRecordFlagsRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DirectoryRecordFlags")
            .field(&self.file_type())
            .finish()
    }
}

impl DirectoryRecordFlagsRaw {
    pub fn file_type(&self) -> DirectoryEntryFileType {
        DirectoryEntryFileType::from_primitive((self.bits() & Self::TypeMask.bits()) as u8)
    }
}

/// Value for a directory entry record (`j_drec_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct DirectoryEntryRecordValueRaw {
    /// The identifier of the inode that this directory entry represents (`file_id`).
    pub file_id: u64,
    /// The time that this directory entry was added to the directory (`date_added`).
    pub date_added: TimeRaw,
    /// The directory entry's flags (`flags`).
    pub flags: DirectoryRecordFlagsRaw,
    /// The directory entry's extended fields (`xfields`).
    ///
    /// An [ExtendedAttributesBlobRaw].
    #[cfg_attr(
        feature = "derive",
        apfs(
            trailing_data = "crate::filesystem_extended_fields::DirectoryRecordExtendedFieldsArray"
        )
    )]
    pub extended_fields: [u8; 0],
}

impl DynamicSized for DirectoryEntryRecordValueRaw {
    // The size of the extended fields isn't declared. So consume all data to
    // end of value data.
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for DirectoryEntryRecordValueRaw {
    type TrailingData = crate::filesystem_extended_fields::DirectoryRecordExtendedFieldsArray;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        let inner = crate::filesystem_extended_fields::ExtendedFieldsArray::new(data)?;

        Ok(inner.into())
    }
}

/// Keys for directory information records (`j_dir_stats_key_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct DirectoryInformationRecordKeyRaw {
    /// Common header.
    pub header: FileSystemKeyRaw,
}

/// Value for a directory information record (`j_dir_stats_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct DirectoryInformationRecordValueRaw {
    /// The number of files and directories contained in the directory (`num_children`).
    pub number_children: u64,

    /// Total size in bytes of all the files stored in this directory and all of its children (`total_size`).
    ///
    /// Hard links contribute to this value.
    pub total_size: u64,

    /// The parent directory's file system object identifier (`chained_key`).
    pub chained_key: u64,

    /// A monotonically incrementing counter tracking how often this inode or its children are modified (`gen_count`).
    pub generation_count: u64,
}

/// Extended attribute record key (`j_xattr_key_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct ExtendedAttributeRecordKeyRaw {
    /// Common header.
    pub header: FileSystemKeyRaw,
    /// Length of the attribute name in bytes.
    ///
    /// Includes NULL terminator.
    pub name_length: u16,
    /// Placeholder for NULL-terminated UTF-8 string data.
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    pub name: [u8; 0],
}

impl DynamicSized for ExtendedAttributeRecordKeyRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.name_length as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for ExtendedAttributeRecordKeyRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

bitflags! {
    /// The flags used in an extended attribute record to provide additional information (`j_xattr_flags`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u16))]
    pub struct ExtendedAttributeFlagsRaw: u16 {
        /// The attribute data is stored in a data stream.
        const DataStream = 0x01;
        /// The attribute data is stored directly in the record.
        const DataEmbedded = 0x02;
        /// The extended attribute record is owned by the file system.
        const FileSystemOwned = 0x04;
        /// Reserved.
        const Reserved8 = 0x08;
    }
}

/// Represents a parsed value from an [ExtendedAttributeRecordValueRaw].
#[cfg(feature = "derive")]
#[derive(Clone, Debug)]
pub enum ExtendedAttributeValue {
    /// Attribute value was embedded in the [ExtendedAttributeRecordValueRaw].
    Embedded(bytes::Bytes),

    /// The attribute value is located in the specified data stream.
    ///
    /// The length of the value is in [ExtendedAttributeRecordValueRaw::data_length].
    StreamId(u64),
}

/// Extended attribute record value (`j_xattr_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct ExtendedAttributeRecordValueRaw {
    /// Bit flags for this value.
    ///
    /// Either [ExtendedAttributeFlagsRaw::DataStream] or [ExtendedAttributeFlagsRaw::DataEmbedded]
    /// must be set.
    pub flags: ExtendedAttributeFlagsRaw,

    /// The length of the extended attribute data.
    pub data_length: u16,

    /// The inline data or an identifier of a data stream containing it.
    ///
    /// For a linked stream identifier, this should be a u64. Otherwise it
    /// is an embedded blob of data.
    #[cfg_attr(feature = "derive", apfs(trailing_data = "ExtendedAttributeValue"))]
    pub data: [u8; 0],
}

impl DynamicSized for ExtendedAttributeRecordValueRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        // For a linked stream, inline data is the u64 stream ID.
        let flags = self.flags;

        if flags.contains(ExtendedAttributeFlagsRaw::DataStream) {
            0..8
        } else {
            0..self.data_length as usize
        }
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for ExtendedAttributeRecordValueRaw {
    type TrailingData = ExtendedAttributeValue;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        // Realign.
        let flags = self.flags;

        if flags.contains(ExtendedAttributeFlagsRaw::DataStream) {
            let buf: [u8; 8] = (&data.as_ref()[0..8])
                .try_into()
                .expect("should have validated source buffer length");
            let id = u64::from_le_bytes(buf);

            Ok(ExtendedAttributeValue::StreamId(id))
        } else {
            Ok(ExtendedAttributeValue::Embedded(data))
        }
    }
}

/// The minimum allowed document identifier.
///
/// Document identifiers must be larger than this.
pub const MINIMUM_DOCUMENT_ID: u32 = 3;
