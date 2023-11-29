// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Data streams.
//!
//! Data streams hold file metadata and content that is too large to fit
//! inside B-tree records.

use crate::{common::PhysicalObjectIdentifierRaw, filesystem::FileSystemKeyRaw};
use core::fmt::{Debug, Formatter};
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::{encryption::*, filesystem::*};

/// Physical extent record key (`j_phys_ext_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct PhysicalExtentRecordKeyRaw {
    /// Common filesystem record header.
    ///
    /// The oid in the header is the physical block address of the
    /// start of the extent.
    pub header: FileSystemKeyRaw,
}

/// The kind of a file system record (`j_obj_kinds`).
///
/// This value is stored in the kind bits of a
/// [PhysicalExtentRecordValueRaw::length_and_kind].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum ObjectKind {
    /// A record of any kind (`APFS_KIND_ANY`).
    ///
    /// Not valid on disk. But can be used internally by implementations.
    Any = 0,

    /// A new record (`APFS_KIND_NEW`).
    ///
    /// This record adds data not in any snapshot.
    New = 1,

    /// An updated record (`APFS_KIND_UPDATE`).
    ///
    /// This record changes part of an existing snapshot.
    Update = 2,

    /// A record that's being deleted (`APFS_KIND_DEAD`).
    ///
    /// Isn't valid in on-disk records.
    Dead = 3,

    /// An update to the reference count of a record (`APFS_KIND_UPDATE_REFCNT`).
    ///
    /// Isn't valid in on-disk records.
    UpdateReferenceCount = 4,

    /// Some other unknown value.
    #[num_enum(alternatives = [5..254])]
    Other = 254,

    /// An invalid record kind (`APFS_KIND_INVALID`).
    Invalid = 255,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct PhysicalExtentLengthAndKindRaw(pub u64);

impl Debug for PhysicalExtentLengthAndKindRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysicalExtentLengthAndKind")
            .field("length", &self.length())
            .field("kind", &self.object_kind())
            .finish()
    }
}

impl PhysicalExtentLengthAndKindRaw {
    /// Obtain the length component of this value.
    pub fn length(&self) -> u64 {
        self.0 & 0x0fffffffffffffff
    }

    /// Obtain the kind component of this value.
    pub fn kind(&self) -> u8 {
        ((self.0 & 0xf000000000000000) >> 60) as u8
    }

    /// Obtain the kind as an [ObjectKind].
    pub fn object_kind(&self) -> ObjectKind {
        ObjectKind::from_primitive(self.kind())
    }
}

/// Physical extent record value (`j_phys_ext_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct PhysicalExtentRecordValueRaw {
    /// The length of the extent and its kind.
    ///
    /// Low 60 bits are length in blocks. High 4 bits are kind.
    ///
    /// The kind is represented by [ObjectKind].
    ///
    /// Volumes without snapshots have kind=NEW.
    pub length_and_kind: PhysicalExtentLengthAndKindRaw,

    /// The filesystem object ID owning this extent.
    ///
    /// If the owner is an inode, this field contains the inode's private_id field
    /// value.
    ///
    /// If the owner is an extended attribute, this field contains the id from
    /// the [ExtendedAttributeRecordKeyRaw]'s header field.
    pub owning_fs_object_id: u64,

    /// The reference count.
    ///
    /// The extent can be deleted when this reaches 0.
    pub reference_count: i32,
}

/// File extent record key (`j_file_extent_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct FileExtentRecordKeyRaw {
    /// Common filesystem record header.
    ///
    /// The oid in the header is the file system object's identifier.
    pub header: FileSystemKeyRaw,

    /// The offset in the file whose data is provided by this extent.
    pub logical_address: u64,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct FileExtentLengthAndFlagsRaw(pub u64);

impl Debug for FileExtentLengthAndFlagsRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileExtentLengthAndFlags")
            .field("length", &self.length())
            .field("flags", &self.flags())
            .finish()
    }
}

impl FileExtentLengthAndFlagsRaw {
    /// The length of the extent.
    pub fn length(&self) -> u64 {
        self.0 & 0x00ffffffffffffff
    }

    /// The bit flags for the extent.
    ///
    /// Currently returns a u8 because no flags are defined.
    pub fn flags(&self) -> u8 {
        ((self.0 & (0xff << 56)) >> 56) as u8
    }
}

/// File extent record value (`j_file_extent_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct FileExtentRecordValueRaw {
    /// A bit field holding the length of the extent and its flags.
    ///
    /// The length in bytes is the lower 56 bits. It must be a multiple of the
    /// block size defined in the container superblock.
    ///
    /// Flags are the upper 8 bits.
    pub length_and_flags: FileExtentLengthAndFlagsRaw,

    /// The physical block that the extent starts at.
    pub physical_block_number: PhysicalObjectIdentifierRaw,

    /// The encryption key or settings used in this extent.
    ///
    /// If the `onekey` encryption flag is set on the volume, this contains the
    /// AES-XTS tweak value.
    ///
    /// Otherwise this matches the [EncryptionStateRecordKeyRaw]'s `object_id` field,
    /// which describes how this file is encrypted.
    ///
    /// The default value is copied from the `default_cryptography_id` field
    /// of the data stream this extent is part of.
    pub cryptography_id: u64,
}

/// Data stream ID record key (`j_dstream_id_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct DataStreamIdRecordKeyRaw {
    /// Common filesystem header.
    ///
    /// The ID is the fs object ID.
    pub header: FileSystemKeyRaw,
}

/// Data stream ID record value (`j_dstream_id_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct DataStreamIdRecordValueRaw {
    /// The reference count.
    ///
    /// The data stream record can be deleted when this reached 0.
    pub reference_count: u32,
}

/// Information about a data stream (`j_dstream_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed(8))]
pub struct DataStreamRaw {
    /// Size of the data in bytes (`size`).
    pub size_bytes: u64,
    /// Total space allocated for the data stream (`alloced_size`).
    pub allocated_size: u64,
    /// Default encryption key or encryption tweak used in this data stream (`default_crypto_id`).
    ///
    /// Should match the `object_id` field in the [FileSystemKeyRaw] for a [EncryptionStateRecordKeyRaw].
    pub default_cryptography_id: u64,
    /// Total number of bytes that have been written to this data stream (`total_bytes_written`).
    ///
    /// Incremented whenever a write operation occurs. Can overflow.
    pub total_bytes_written: u64,
    /// Total number of bytes that have been read from this data stream (`total_bytes_read`).
    ///
    /// Incremented whenever a read operation occurs. Can overflow.
    pub total_bytes_read: u64,
}

/// A data stream holding extended attributes data (`j_xattr_dstream_t`).
///
/// To access data, read the object ID and then find its extents.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct ExtendedAttributeDataStreamRaw {
    /// The identifier for the data stream.
    pub extended_attribute_object_id: u64,
    /// The data stream that owns this record.
    pub data_stream: DataStreamRaw,
}
