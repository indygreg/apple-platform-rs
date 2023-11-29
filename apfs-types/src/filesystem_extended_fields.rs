// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Filesystem extended fields.

use crate::DynamicSized;
use bitflags::bitflags;
use core::fmt::Debug;
use core::ops::Range;
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(feature = "derive")]
use {
    crate::{
        filesystem::DirectoryInformationRecordValueParsed, DiskStruct, ParseError, ParsedDiskStruct,
    },
    apfs_derive::ApfsData,
    core::fmt::Formatter,
};

#[cfg(doc)]
use crate::{common::*, data_stream::*, filesystem::*};

/// Extended field types for directory records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum DirectoryRecordExtendedFieldType {
    /// The sibling ID for this record (`DREC_EXT_TYPE_SIBLING_ID`).
    ///
    /// The associated sibling link record has the same ID in
    /// [SiblingLinkRecordKey.sibling_id].
    ///
    /// Used only for hard links.
    ///
    /// Value is a u64.
    SiblingId = 1,

    #[num_enum(catch_all)]
    Other(u8),
}

/// Extended field types for inode records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum InodeExtendedFieldType {
    /// The transaction ID for a snapshot (`INO_EXT_TYPE_SNAP_XID`).
    ///
    /// Values is a [TransactionIdentifierRaw].
    SnapshotTransactionIdentifier = 1,

    /// Virtual object ID of the filesystem tree corresponding to a snapshot's extent delta list (`INO_EXT_TYPE_DELTA_TREE_OID`).
    ///
    /// Value is an [ObjectIdentifierRaw].
    DeltaTreeOid = 2,

    /// File's document identifier (`INO_EXT_TYPE_DOCUMENT_ID`).
    ///
    /// The document identifier is preserved for logical paths during replacement.
    /// The identifier should be preserved when a path is logically replaced. e.g.
    /// during atomic saves.
    ///
    /// Value must be greater than [MINIMUM_DOCUMENT_ID] and less than u32::max()-1.
    ///
    /// Value is a u32.
    DocumentId = 3,

    /// The name of the file (`INO_EXT_TYPE_NAME`).
    ///
    /// Used only for hard links. The name in the inode is the name of the
    /// primary link to the file. This is the name of the hard link.
    ///
    /// Value is NULL-terminated UTF-8 string.
    Name = 4,

    /// Previous file's size (`INO_EXT_TYPE_PREV_FSIZE`).
    ///
    /// Used during crash recovery. If this is set on an inode record, truncate
    /// the file to the size in this attribute.
    ///
    /// Value is a u64.
    PreviousFileSize = 5,

    /// Reserved (`INO_EXT_TYPE_RESERVED_6`).
    Reserved6 = 6,

    /// Opaque data used by Finder (`INO_EXT_TYPE_FINDER_INFO`).
    ///
    /// Value is 32 bytes.
    FinderInfo = 7,

    /// A data stream (`INO_EXT_TYPE_DSTREAM`).
    ///
    /// Value is a [DataStreamRaw].
    DataStream = 8,

    /// Reserved (`INO_EXT_TYPE_RESERVED_9`).
    Reserved9 = 9,

    /// Statistics about a directory (`INO_EXT_TYPE_DIR_STATS_KEY`).
    ///
    /// Value is a [DirectoryInformationRecordValueRaw].
    DirectoryStatsKey = 10,

    /// UUID of a filesystem that's automatically mounted in this directory (`INO_EXT_TYPE_FS_UUID`).
    ///
    /// Value matches the [ApfsSuperblock.volume_id] field.
    ///
    /// Value is a [UuidRaw].
    MountedFilesystemUuid = 11,

    /// Reserved (`INO_EXT_TYPE_RESERVED_12`).
    Reserved12 = 12,

    /// The number of sparse bytes in the data stream (`INO_EXT_TYPE_SPARSE_BYTES`).
    ///
    /// Value is a u64.
    SparseBytes = 13,

    /// Device identifier for a block or character device (`INO_EXT_TYPE_RDEV`).
    ///
    /// Stores the same content as the `st_dev` field of the common POSIX stat
    /// data structure.
    ///
    /// Value is a u32.
    DeviceIdentifier = 14,

    /// Information about a purgeable file (`INO_EXT_TYPE_PURGEABLE_FLAGS`).
    ///
    /// Don't create this field. Omit this extended attribute when copying.
    PurgeableFlags = 15,

    /// Inode number of the sync-root tree this file originally belonged to (`INO_EXT_TYPE_ORIG_SYNC_ROOT_ID`).
    ///
    /// The inode should have [InodeFlagsRaw::IsSyncRoot] set.
    OriginalSyncRootId = 16,

    #[num_enum(catch_all)]
    Other(u8),
}

bitflags! {
    /// Extended field flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u8))]
    pub struct ExtendedFieldFlagsRaw: u8 {
        /// The data in this extended field depends on the file's data (`XF_DATA_DEPENDENT`).
        ///
        /// When file data changes, this extended field should be updated.
        ///
        /// If the field data is unknown, this field should be removed.
        const DataDependent = 0x01;

        /// Omit this extended field when copying a file (`XF_DO_NOT_COPY`).
        const DoNotCopy = 0x02;

        /// Reserved (`XF_RESERVED_4`).
        const Reserved4 = 0x04;

        /// Copy this extended field to new entries in a directory (XF_CHILDREN_INHERIT`).
        const ChildrenInherit = 0x08;

        /// Extended field was added by a userspace program (`XF_USER_FIELD`).
        const UserField = 0x10;

        /// Extended field was added by the kernel, APFS, or by other system components (`XF_SYSTEM_FIELD`).
        ///
        /// Fields should not be modifiable by userland processes.
        const SystemField = 0x20;

        /// Reserved (`XF_RESERVED_40`).
        const Reserved40 = 0x40;

        /// Reserved (`XF_RESERVED_80`).
        const Reserved80 = 0x80;

        const _ = !0;
    }
}

/// Metadata for an extended field (`x_field_t`).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
pub struct ExtendedFieldRaw {
    /// The type of the extended field (`x_type`).
    ///
    /// Can be either a [DirectoryRecordExtendedFieldType] or [InodeExtendedFieldType]
    /// depending on the type of entity this record is associated with.
    pub typ: u8,

    /// Flags for this field (`x_flags`).
    pub flags: ExtendedFieldFlagsRaw,

    /// Size in bytes of the data for this extended field (`x_size`).
    pub size_bytes: u16,
}

/// A collection of extended attributes (`xf_blob_t`).
///
/// This is the value for [DirectoryEntryRecordValue.extended_fields] and
/// [InodeRecordValueRaw.extended_fields].
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ExtendedAttributesBlobRaw {
    /// The number of extended attributes (`xf_num_exts`).
    pub count: u16,

    /// The size in bytes of inline data that follows (`xf_used_data`).
    pub size_bytes: u16,

    /// The extended fields data (`xf_data`).
    ///
    /// An array of [ExtendedFieldRaw] followed by the data for each field.
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub data: [u8; 0],
}

impl DynamicSized for ExtendedAttributesBlobRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.size_bytes as usize
    }
}

/// Represents an array of generic extended fields/attributes.
///
/// This is like a parsed version of [ExtendedAttributesBlobRaw].
///
/// This type facilitates reading the array of [ExtendedFieldRaw] present
/// in [DirectoryEntryRecordValueRaw] and [InodeRecordValueRaw] and
/// obtaining a view into their raw payload.
///
/// You likely want to use a [DirectoryRecordExtendedFieldsArray] or
/// [InodeRecordExtendedFieldsArray] to get more strongly typed entities
/// out of the raw data.
#[cfg(feature = "derive")]
#[derive(Clone)]
pub struct ExtendedFieldsArray {
    buf: bytes::Bytes,
    count: usize,
}

#[cfg(feature = "derive")]
impl Debug for ExtendedFieldsArray {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(feature = "derive")]
impl ExtendedFieldsArray {
    /// Construct an instance from bytes.
    ///
    /// Bytes begins at the [ExtendedAttributesBlobRaw] header.
    pub fn new(buf: bytes::Bytes) -> Result<Self, ParseError> {
        if buf.is_empty() {
            Ok(Self { buf, count: 0 })
        } else {
            let blob = ExtendedAttributesBlobRaw::parse_bytes(buf.as_ref())?;

            let header_len = core::mem::size_of::<ExtendedAttributesBlobRaw>();
            let wanted = blob.size_bytes as usize + header_len;

            if buf.len() < wanted {
                return Err(ParseError::InputTooSmall);
            }

            let buf = buf.slice(header_len..);

            Ok(Self {
                buf,
                count: blob.count as _,
            })
        }
    }

    /// Iterate over extended fields in this array.
    ///
    /// Values are not decoded as the types of values vary depending on the
    /// data structure they are attached to.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<(ExtendedFieldParsed, bytes::Bytes), ParseError>> + '_ {
        let mut offset = 0;
        let mut data_offset = self.count * core::mem::size_of::<ExtendedFieldRaw>();

        (0..self.count).map(move |_| {
            let ef = ExtendedFieldParsed::from_bytes(
                self.buf
                    .slice(offset..offset + core::mem::size_of::<ExtendedFieldRaw>()),
            )?;
            offset += core::mem::size_of::<ExtendedFieldRaw>();

            let end = data_offset + ef.size_bytes as usize;

            if end > self.buf.len() {
                return Err(ParseError::InputTooSmall);
            }

            let data = self.buf.slice(data_offset..end);
            data_offset = end;

            // Values are 8 byte aligned relative to start of values data.
            let remaining = ef.size_bytes as usize % 8;
            if remaining != 0 {
                data_offset += 8 - remaining;
            }

            Ok((ef, data))
        })
    }
}

/// Represents a parsed/typed extended attribute field for a directory record.
///
/// Instances are derived from [ExtendedFieldRaw] in [DirectoryEntryRecordValueRaw].
#[cfg(feature = "derive")]
#[derive(Clone, Debug)]
pub enum DirectoryRecordExtendedFieldValue {
    SiblingId(u64),
    Other(u8, bytes::Bytes),
}

/// An extended field in a [DirectoryEntryRecordValueRaw].
#[cfg(feature = "derive")]
#[derive(Clone, Debug)]
pub struct DirectoryRecordExtendedField {
    /// Flags for this field.
    pub flags: ExtendedFieldFlagsRaw,
    /// Value for this field.
    pub value: DirectoryRecordExtendedFieldValue,
}

#[cfg(feature = "derive")]
impl DirectoryRecordExtendedField {
    /// Construct an instance from an extended field and its payload.
    pub fn new(ef: ExtendedFieldParsed, data: bytes::Bytes) -> Result<Self, ParseError> {
        let typ = DirectoryRecordExtendedFieldType::from_primitive(ef.typ);

        let value = match typ {
            DirectoryRecordExtendedFieldType::SiblingId => {
                let buf: [u8; 8] = (&data.as_ref()[0..8])
                    .try_into()
                    .map_err(|_| ParseError::InputTooSmall)?;
                let id = u64::from_le_bytes(buf);

                DirectoryRecordExtendedFieldValue::SiblingId(id)
            }
            DirectoryRecordExtendedFieldType::Other(typ) => {
                DirectoryRecordExtendedFieldValue::Other(typ, data)
            }
        };

        Ok(DirectoryRecordExtendedField {
            flags: ef.flags,
            value,
        })
    }
}

/// Represents extended fields/attributes in a [DirectoryEntryRecordValueRaw].
#[cfg(feature = "derive")]
#[derive(Clone)]
pub struct DirectoryRecordExtendedFieldsArray {
    inner: ExtendedFieldsArray,
}

#[cfg(feature = "derive")]
impl From<ExtendedFieldsArray> for DirectoryRecordExtendedFieldsArray {
    fn from(inner: ExtendedFieldsArray) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "derive")]
impl Debug for DirectoryRecordExtendedFieldsArray {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(feature = "derive")]
impl DirectoryRecordExtendedFieldsArray {
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<DirectoryRecordExtendedField, ParseError>> + '_ {
        self.inner
            .iter()
            .map(|res| res.and_then(|(ef, data)| DirectoryRecordExtendedField::new(ef, data)))
    }
}

/// Represents a parsed/typed extended attribute field value for an inode.
///
/// Instances are decoded from [ExtendedFieldRaw] entries in [InodeRecordValueRaw]
/// filesystem b-tree records.
#[cfg(feature = "derive")]
#[derive(Clone, Debug)]
pub enum InodeExtendedFieldValue {
    SnapshotTransactionIdentifier(crate::common::TransactionIdentifierParsed),
    DeltaTreeOid(crate::common::VirtualObjectIdentifierParsed),
    DocumentId(u32),
    Name(crate::pod::ApfsString),
    PreviousFileSize(u64),
    Reserved6,
    FinderInfo([u8; 32]),
    DataStream(crate::data_stream::DataStreamParsed),
    Reserved9,
    DirectoryStatsKey(DirectoryInformationRecordValueParsed),
    MountedFilesystemUuid(crate::common::UuidParsed),
    Reserved12,
    SparseBytes(u64),
    DeviceIdentifier(u32),
    PurgeableFlags,
    OriginalSyncRootId(crate::common::VirtualObjectIdentifierParsed),
    Other(u8, bytes::Bytes),
}

#[cfg(feature = "derive")]
impl InodeExtendedFieldValue {
    /// Construct an instance from bytes and its enumerated type.
    pub fn from_record(
        typ: InodeExtendedFieldType,
        data: bytes::Bytes,
    ) -> Result<Self, ParseError> {
        match typ {
            InodeExtendedFieldType::SnapshotTransactionIdentifier => {
                let xid = crate::common::TransactionIdentifierParsed::from_bytes(data)?;
                Ok(Self::SnapshotTransactionIdentifier(xid))
            }
            InodeExtendedFieldType::DeltaTreeOid => {
                let oid = crate::common::VirtualObjectIdentifierParsed::from_bytes(data)?;
                Ok(Self::DeltaTreeOid(oid))
            }
            InodeExtendedFieldType::DocumentId => {
                let id = u32::parse_bytes(data.as_ref())?;
                Ok(Self::DocumentId(id))
            }
            InodeExtendedFieldType::Name => {
                let s = crate::pod::ApfsString::from_bytes(data)?;
                Ok(Self::Name(s))
            }
            InodeExtendedFieldType::PreviousFileSize => {
                let v = u64::parse_bytes(data.as_ref())?;
                Ok(Self::PreviousFileSize(v))
            }
            InodeExtendedFieldType::Reserved6 => Ok(Self::Reserved6),
            InodeExtendedFieldType::FinderInfo => {
                let v = data.as_ref().get(0..32).ok_or(ParseError::InputTooSmall)?;
                Ok(Self::FinderInfo(v.try_into().unwrap()))
            }
            InodeExtendedFieldType::DataStream => {
                let v = crate::data_stream::DataStreamParsed::from_bytes(data)?;
                Ok(Self::DataStream(v))
            }
            InodeExtendedFieldType::Reserved9 => Ok(Self::Reserved9),
            InodeExtendedFieldType::DirectoryStatsKey => {
                let v = DirectoryInformationRecordValueParsed::from_bytes(data)?;
                Ok(Self::DirectoryStatsKey(v))
            }
            InodeExtendedFieldType::MountedFilesystemUuid => {
                let v = crate::common::UuidParsed::from_bytes(data)?;
                Ok(Self::MountedFilesystemUuid(v))
            }
            InodeExtendedFieldType::Reserved12 => Ok(Self::Reserved12),
            InodeExtendedFieldType::SparseBytes => {
                let v = u64::parse_bytes(data.as_ref())?;
                Ok(Self::SparseBytes(v))
            }
            InodeExtendedFieldType::DeviceIdentifier => {
                let v = u32::parse_bytes(data.as_ref())?;
                Ok(Self::DeviceIdentifier(v))
            }
            InodeExtendedFieldType::PurgeableFlags => Ok(Self::PurgeableFlags),
            InodeExtendedFieldType::OriginalSyncRootId => {
                let v = crate::common::VirtualObjectIdentifierParsed::from_bytes(data)?;
                Ok(Self::OriginalSyncRootId(v))
            }
            InodeExtendedFieldType::Other(typ) => Ok(Self::Other(typ, data)),
        }
    }
}

/// An extended field for an Inode record.
#[cfg(feature = "derive")]
#[derive(Clone, Debug)]
pub struct InodeExtendedField {
    /// Flags for this extended field.
    pub flags: ExtendedFieldFlagsRaw,
    /// Enumerated value for this extended field.
    pub value: InodeExtendedFieldValue,
}

#[cfg(feature = "derive")]
impl InodeExtendedField {
    pub fn new(ef: ExtendedFieldParsed, data: bytes::Bytes) -> Result<Self, ParseError> {
        let typ = InodeExtendedFieldType::from_primitive(ef.typ);
        let value = InodeExtendedFieldValue::from_record(typ, data)?;

        Ok(Self {
            flags: ef.flags,
            value,
        })
    }
}

/// Represents the extended fields in an [InodeRecordValueRaw].
#[cfg(feature = "derive")]
#[derive(Clone)]
pub struct InodeRecordExtendedFieldsArray {
    inner: ExtendedFieldsArray,
}

#[cfg(feature = "derive")]
impl From<ExtendedFieldsArray> for InodeRecordExtendedFieldsArray {
    fn from(inner: ExtendedFieldsArray) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "derive")]
impl Debug for InodeRecordExtendedFieldsArray {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(feature = "derive")]
impl InodeRecordExtendedFieldsArray {
    pub fn iter(&self) -> impl Iterator<Item = Result<InodeExtendedField, ParseError>> + '_ {
        self.inner
            .iter()
            .map(|res| res.and_then(|(ef, data)| InodeExtendedField::new(ef, data)))
    }
}
