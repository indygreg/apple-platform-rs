// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Encryption.

use crate::{common::UuidRaw, filesystem::FileSystemKeyRaw, object::ObjectHeaderRaw, DynamicSized};
use core::ops::{Range, RangeFrom};
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::{common::*, filesystem::*};

/// Cryptography ID value indicating the use of software cryptography (`CRYPTO_SW_ID`).
///
/// There is no encryption key associated with this encryption mode. All the fields of
/// [EncryptionStateRecordValueRaw] are 0.
pub const SOFTWARE_CRYPTOGRAPHY_ID: u64 = 4;

/// Reserved. Should not be used (`CRYPTO_RESERVED_5`).
pub const CRYPTOGRAPHY_ID_RESERVED: u64 = 5;

/// Identifier of a placeholder encryption state when cloning files (`APFS_UNASSIGNED_CRYPTO_ID`).
pub const UNASSIGNED_CRYPTOGRAPHY_ID: u64 = 0;

/// A protection class.
pub type KeyClass = u32;

/// An OS version and build number.
///
/// 2 bytes for the major version number as an unsigned integer.
/// 2 bytes for the minor version letter as an ASCII character.
/// 4 bytes for the build number as an unsigned integer.
pub type KeyOsVersion = u32;

/// A version number for an encryption key.
pub type KeyRevision = u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum ProtectionClass {
    /// Directory default (`PROTECTION_CLASS_DIR_NONE`).
    ///
    /// Files with this class use the containing directory's default protection
    /// class defined on [InodeRecordValueRaw::default_protection_class].
    None = 0,
    /// Corresponds to `FileProtectionType.complete` (`PROTECTION_CLASS_A`).
    A = 1,
    /// Corresponds to `FileProtectionType.completeUnlessOpen` (`PROTECTION_CLASS_B`)
    B = 2,
    /// Protected until first user authentication (`PROTECTION_CLASS_C`).
    ///
    /// Corresponds to `FileProtectionType.completeUntilFirstUserAuthentication`.
    C = 3,
    /// No protection (`PROTECTION_CLASS_D`).
    ///
    /// Corresponds to `FileProtectionType.none`.
    D = 4,
    /// No protection with non-persistent key (`PROTECTION_CLASS_F`).
    ///
    /// Same as `D` except the key isn't stored in any persistent way.
    /// Suitable for temporary files.
    F = 5,
    /// Unknown (`PROTECTION_CLASS_M`).
    M = 6,

    #[num_enum(catch_all)]
    Unknown(u32),
}

/// Encryption state record key (`j_crypto_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct EncryptionStateRecordKeyRaw {
    /// Common filesystem object header (`hdr`).
    pub header: FileSystemKeyRaw,
}

/// Encryption state record value (`j_crypto_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed(4))]
pub struct EncryptionStateRecordValueRaw {
    /// The reference count (`refcnt`).
    pub reference_count: u32,
    /// The encryption state information (`state`).
    ///
    /// If this record is used by the filesystem tree instead of a file, this is
    /// a [WrappedMetaCryptoStateRaw] and the key used is the Volume Encryption Key.
    pub state: WrappedCryptoStateRaw,
}

// This struct itself is static sized but the state is dynamic. That
// makes us dynamic.
impl DynamicSized for EncryptionStateRecordValueRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

pub const MAX_WRAPPED_KEY_SIZE: u16 = 128;

/// A wrapped key used for per-file encryption (`wrapped_crypto_state_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed(2))]
pub struct WrappedCryptoStateRaw {
    /// The major version for this structure's layout (`major_version`).
    ///
    /// 5 is known to be the current value.
    pub major_version: u16,
    /// The minor version for this struct's layout (`minor_version`).
    ///
    /// 0 is known to be the current value.
    pub minor_version: u16,
    /// The encryption state's flags (`cpflags`).
    pub flags: u32,
    /// The protection class associated with the key (`persistent_class`)
    pub persistent_class: KeyClass,
    /// The version of the OS that created this structure (`key_os_version`).
    pub key_os_revision: KeyOsVersion,
    /// The version of the key (`key_revision`).
    ///
    /// Set to 1 when creating. Increment by 1 when rolling keys.
    pub key_revision: KeyRevision,
    /// The size, in bytes, of the wrapped key data (`key_len`).
    pub key_length: u16,
    /// Wrapped key data (`persistent_key`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub persistent_key: [u8; 0],
}

impl DynamicSized for WrappedCryptoStateRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.key_length as usize
    }
}

/// Information about the volume encryption key (`wrapped_meta_crypto_state_t`).
///
/// Identical to [WrappedCryptoStateRaw] except this variant lacks key data.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed(2))]
pub struct WrappedMetaCryptoStateRaw {
    /// The major version for this structure's layout (`major_version`).
    pub major_version: u16,
    /// The minor version for this structure's layout (`minor_version`).
    pub minor_version: u16,
    /// The encryption state's flags (`cpflags`).
    pub flags: u32,
    /// The protection class associated with the key (`persistent_class`).
    pub persistent_class: KeyClass,
    /// The version of the OS that created this structure (`key_os_version`).
    pub key_os_version: KeyOsVersion,
    /// The version of the key (`key_revision`).
    pub key_revision: KeyRevision,
    /// Reserved (`unused`).
    pub unused: u16,
}

/// A description of the type of information in a keybag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum KeybagTag {
    /// Reserved. Should never occur. (`KB_TAG_UNKNOWN`).
    Unknown = 0,
    /// Reserved. (`KB_TAG_RESERVED_1`)
    ///
    /// Don't create entries with this value but preserve when seen.
    Reserved1 = 1,

    /// (`KB_TAG_VOLUME_KEY`)
    ///
    /// Key data stores a wrapped Volume Encryption Key.
    ///
    /// Only valid in a container's keybag.
    VolumeKey = 2,

    /// Stores location of data (`KB_TAG_VOLUME_UNLOCK_RECORDS`).
    ///
    /// In a container's keybag, the key data stores the location of the
    /// volume's keybag.
    ///
    /// In a volume's keybag, key data stored a wrapped Key Encryption Key.
    /// Stored as a [PhysicalAddressRangeRaw] whose data is a [KeybagRaw].
    VolumeUnlockRecords = 3,

    /// Stores user-provided password hint as plaint text (`KB_TAG_VOLUME_PASSPHRASE_HINT`).
    ///
    /// Only valid on a volume keybag.
    VolumePassphraseHint = 4,

    /// Key data stores a key used to wrap a media key (`KB_TAG_WRAPPING_M_KEY`).
    WrappingMediaKey = 5,

    /// Key data stores a key used to wrap media keys on a volume (`KB_TAG_VOLUME_M_KEY`).
    VolumeMediaKey = 6,

    /// Reserved (`KB_TAG_RESERVED_F8`).
    ///
    /// Don't create but preserve.
    ReservedF8 = 0xf8,

    #[num_enum(catch_all)]
    Other(u16),
}

/// Maximum size of a keybag entry for volumes.
pub const VOLUME_KEYBAG_ENTRY_MAX_SIZE: usize = 512;

// TODO
// PERSONAL_RECOVERY_KEY_UUID = ”EBC6C064-0000-11AA-AA11-00306543ECAC”;

/// An entry in a keybag (`keybag_entry_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct KeybagEntryRaw {
    /// A UUID (`ke_uuid`).
    ///
    /// In a container's keybag, the UUID of a volume.
    ///
    /// In a volume's keybag, the UUID of a user.
    pub uuid: UuidRaw,

    /// The type of data stored in this entry (`ke_tag`).
    ///
    /// Value is a [KeybagTag].
    pub tag: u16,

    /// Length in bytes of the keybag's data (`ke_keylen`).
    ///
    /// Must be less than [VOLUME_KEYBAG_ENTRY_MAX_SIZE].
    pub key_length: u16,

    /// Padding bytes (`padding`).
    ///
    /// Populate with 0s when creating a new entry and preserve value during
    /// modifications.
    pub padding: [u8; 4],

    /// Keybag entry's data (`ke_keydata`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub key_data: [u8; 0],
}

impl DynamicSized for KeybagEntryRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.key_length as usize
    }
}

/// Current keybag version.
pub const KEYBAG_VERSION: u16 = 2;

/// A keybag (`kb_lcoker_t`).
///
/// A keybag stores wrapped encryption keys and metadata needed to unwrap them.
///
/// There is a keybag for a container and each volume within in.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct KeybagRaw {
    /// The keybag's version (`kl_version`).
    ///
    /// Should be [KEYBAG_VERSION].
    pub version: u16,

    /// The number of entries in this keybag (`kl_nkeys`).
    pub number_entries: u16,

    /// Size in bytes of data stored in the `entries` field (`kl_nbytes`).
    pub entries_bytes: u32,

    /// Reserved (`padding`).
    ///
    /// Populate with 0 for new keybags and preserve when modifying.
    pub padding: [u8; 8],

    /// The keybag's entries (`kl_entries`).
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub entries: [KeybagEntryRaw; 0],
}

impl DynamicSized for KeybagRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.entries_bytes as usize
    }
}

/// A keybag stored as a container-layer object (`media_keybag_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct MediaKeybagRaw {
    /// Block object header (`mk_obj`).
    pub object: ObjectHeaderRaw,
    /// The keybag (`mk_locker`).
    pub keybag: KeybagRaw,
}
