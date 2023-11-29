// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sealed volumes.
//!
//! Sealed volumes contain a digest of their filesystem. This allows
//! verification that a filesystem hasn't been modified after sealing.

use crate::{
    common::TransactionIdentifierRaw, filesystem::FileSystemKeyRaw, object::ObjectHeaderRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::{Range, RangeFrom};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::common::*;

/// Integrity metadata version constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum IntegrityMetadataVersion {
    /// (`INTEGRITY_META_VERSION_INVALID`)
    Invalid = 0,
    /// (`INTEGRITY_META_VERSION_1`)
    One = 1,
    /// (`INTEGRITY_META_VERSION_2`)
    Two = 2,
}

bitflags! {
    /// Integrity metadata flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct IntegrityMetadataFlagsRaw: u32 {
        /// The volume was modified after being sealed (`APFS_SEAL_BROKEN`).
        ///
        /// If set, [IntegrityMetadataRaw::broken_xid] contains the transaction identifier
        /// breaking the seal.
        const SealBroken = 1;

        const _ = !0;
    }
}

/// Supported digest algorithms (`apfs_hash_type_t`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum ApfsHashType {
    /// An invalid hash algorithm (`APFS_HASH_INVALID`).
    Invalid = 0,
    /// SHA-256 (`APFS_HASH_SHA256`).
    Sha256 = 0x01,
    /// SHA-512/256 variant of Secure Hash Algorithm 2 (`APFS_HASH_SHA512_256`).
    Sha512_256 = 0x02,
    /// SHA-384 (`APFS_HASH_SHA384`).
    Sha384 = 0x03,
    /// SHA-512 (`APFS_HASH_SHA512`).
    Sha512 = 0x04,
}

impl Default for ApfsHashType {
    fn default() -> Self {
        Self::Sha256
    }
}

impl ApfsHashType {
    /// The size in bytes of hashes produced by this format.
    pub fn hash_size(&self) -> usize {
        match self {
            Self::Invalid => 0,
            // APFS_HASH_CCSHA256_SIZE
            Self::Sha256 => 32,
            // APFS_HASH_CCSHA512_256_SIZE
            Self::Sha512_256 => 32,
            // APFS_HASH_CCSHA384_SIZE
            Self::Sha384 => 48,
            // APFS_HASH_CCSHA512_SIZE
            Self::Sha512 => 64,
        }
    }
}

/// Integrity metadata for a sealed volume (`integrity_meta_phys_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct IntegrityMetadataRaw {
    /// Common object header (`im_o`).
    pub object: ObjectHeaderRaw,

    /// Version of this data structure (`im_version`).
    ///
    /// Value are [IntegrityMetadataVersion].
    pub version: u32,

    /// Flags describing the metadata (`im_flags`).
    pub flags: IntegrityMetadataFlagsRaw,

    /// The hash algorithm being used (`im_hash_type`).
    ///
    /// Values are [ApfsHashType].
    pub hash_type: u32,

    /// The offset in bytes of the root hash relative to the start of this struct (`im_root_hash_offset`).
    pub root_hash_offset: u32,

    /// The transaction ID that broke the volume's seal (`im_broken_xid`).
    ///
    /// 0 if the seal isn't broken.
    pub broken_xid: TransactionIdentifierRaw,

    /// Reserved (`im_reserved`).
    ///
    /// Only present in version 2 and later.
    pub reserved: [u64; 9],
}

/// File extent tree record key (`fext_tree_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct FileExtentTreeRecordKeyRaw {
    /// The object identifier of the file (`private_id`).
    ///
    /// Value is the object ID part of the common filesystem record key.
    pub private_id: u64,

    /// Byte offset within the file's data for the data stored in this extent (`logical_addr`).
    pub logical_address: u64,
}

/// File extent tree record value (`fext_tree_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct FileExtentTreeRecordValueRaw {
    /// Bit field containing length of the extent and its flags (`len_and_flags`).
    ///
    /// Length is the lower 56 bits.
    /// Flags is the upper 8 bits.
    ///
    /// Length must be a multiple of the block size defined in the container superblock.
    ///
    /// No flags are currently defined.
    pub length_and_flags: u64,

    /// The physical block address that the extent starts at (`phys_block_num`).
    pub physical_block_number: u64,
}

/// The type of a file info record (`j_obj_file_info_type`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum FileInfoRecordType {
    /// The file info record contains a hash of file data (`APFS_FILE_INFO_DATA_HASH`).
    DataHash = 1,
}

/// File info record key (`j_file_info_key-t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct FileInfoRecordKeyRaw {
    /// Common filesystem record header (`hdr`).
    ///
    /// Object ID in header is the file system object's ID.
    pub header: FileSystemKeyRaw,

    /// Bit field containing address and other info (`info_and_lba`).
    ///
    /// The lower 56 bits is a [PhysicalAddressRaw].
    /// The upper 8 bits is a [FileInfoRecordType].
    pub info_and_address: u64,
}

/// A hash of file data (`j_file_data_hash_val_t`).
#[derive(Clone, Debug, Copy)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct FileDataHashValueRaw {
    /// The length in blocks of the data segment that was hashed (`hashed_len`).
    pub hashed_blocks_count: u16,

    /// Length in bytes of the hash data (`hash_size`).
    ///
    /// This should match the value returned by [ApfsHashType::hash_size()] for
    /// the hash type defined in [IntegrityMetadataRaw::hash_type].
    pub hash_size: u8,

    /// The hash data (`hash`).
    ///
    /// Length is `hash_size`.
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub hash: [u8; 0],
}

impl DynamicSized for FileDataHashValueRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.hash_size as usize
    }
}

/// File info record value (`j_file_info_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct FileInfoRecordValueRaw {
    /// A hash of file data (`dhash`).
    ///
    /// This field is strictly speaking a union keying off the [FileInfoRecordType]
    /// variant for the [FileInfoRecordKeyRaw]. However, since there is only 1
    /// variant, we hard code it.
    pub hash: FileDataHashValueRaw,
}

impl DynamicSized for FileInfoRecordValueRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}
