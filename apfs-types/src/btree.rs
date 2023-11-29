// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! B-tree primitives.

use crate::{
    common::ObjectIdentifierRaw, object::ObjectHeaderRaw, object::StorageClass, DynamicSized,
};
use bitflags::bitflags;
use core::ops::RangeFrom;

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

/// A B-Tree location offset indicating an invalid location (`BTOFF_INVALID`).
pub const BTREE_INVALID_OFFSET: u16 = 0xffff;

/// A location within a B-tree node (`nloc_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct NodeLocationRaw {
    /// The offset, in bytes (`off`).
    ///
    /// For values, the offset is implicitly negative.
    pub offset: u16,

    /// The length, in bytes (`len`).
    pub length: u16,
}

/// The location of a fixed-size key and value inside a B-tree node (`kvoff_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct KeyValueOffsetRaw {
    /// The offset of the key (`k`).
    pub key: u16,
    /// The offset of the value (`v`).
    pub value: u16,
}

/// The location of a key and value in a B-tree node (`kvloc_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct KeyValueLocationRaw {
    /// The location of the key (`k`).
    pub key: NodeLocationRaw,
    /// The location of the value (`v`).
    pub value: NodeLocationRaw,
}

/// The maximum length of a hash that can be stored in [BTreeIndexNodeValueRaw].
pub const BTREE_NODE_HASH_MAX_SIZE: usize = 64;

/// B-tree node values for non-leaf nodes of hashed B-trees (`btn_index_node_val_t`).
///
/// Normally the values of non-leaf node entries are object identifiers.
/// In hashed B-trees they are this structure instead.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct BTreeIndexNodeValueRaw {
    /// Object identifier of the child node (`binv_child_oid`).
    pub child_oid: ObjectIdentifierRaw,

    /// The hash of the child node.
    ///
    /// The hash algorithm used by the tree determines the length of
    /// the hash.
    ///
    /// The hash is computed from the entire node object's data.
    ///
    /// Extra bytes after the computed hash and [BTREE_NODE_HASH_MAX_SIZE]
    /// should be set to 0 and preserved when modifying nodes.
    pub child_hash: [u8; BTREE_NODE_HASH_MAX_SIZE],
}

bitflags! {
    /// The flags used to describe configuration options for a B-tree.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct BTreeFlagsRaw: u32 {
        /// BTree consumer should enable optimizations to make key comparisons fast (`BTREE_UINT64_KEYS`).
        ///
        /// This is a hint to implementations.
        const UInt64Keys = 0x01;

        /// Enable optimizations to keep the B-tree compact during sequential inserts (`BTREE_SEQUENTIAL_INSERT`).
        ///
        /// This is a hint to implementations.
        ///
        /// Normally nodes are split in half when almost full. This flag changes
        /// behavior to instead create a new node, ensuring the old node remains
        /// nearly full.
        const SequentialInsert = 0x02;

        /// The table of contents can have keys with no corresponding value (`BTREE_ALLOW_GHOSTS`).
        ///
        /// A ghost value has a location offset of [BTREE_INVALID_OFFSET].
        ///
        /// A ghost can mean a key has been deleted and should be ignored.
        /// Or its value could be implicit based on context.
        ///
        /// Implicit ghost values can be used to increase storage density of nodes
        /// by avoiding value storage.
        const AllowGhosts = 0x04;

        /// Nodes in this B-tree use ephemeral object identifiers to link to child nodes (`BTREE_EPHEMERAL`).
        ///
        /// Exclusive with [Self::Physical]. If neither set, OIDs are virtual.
        const Ephemeral = 0x08;

        /// Nodes in this B-tree use physical object identifiers to link to child nodes (`BTREE_PHYSICAL`).
        ///
        /// Exclusive with [Self::Ephemeral]. If neither set, OIDs are virtual.
        const Physical = 0x10;

        /// The B-tree isn't persisted across unmounting (`BTREE_NONPERSISTENT`).
        ///
        /// Only valid when [Self::Ephemeral] is set. It essentially says to not
        /// save this tree in the checkpoint area.
        const NonPersistent = 0x20;

        /// Keys and values aren't required to be 8 byte aligned (`BTREE_KV_NONALIGNED`).
        ///
        /// 8 byte alignment is the default unless this is set.
        const KeyValueNonAligned = 0x40;

        /// The non-leaf nodes of this tree store a hash of their child nodes (`BTREE_HASHED`).
        ///
        /// If set, all nodes of this tree should have [BTreeNodeFlagsRaw::Hashed]
        /// set. The hash is stored in [BTreeIndexNodeValueRaw::child_hash].
        const Hashed = 0x80;

        /// Nodes of this tree are stored without object headers (`BTREE_NOHEADER`).
        ///
        /// If set, all nodes in this tree should have [BTreeNodeFlagsRaw::NoHeader] set.
        const NoHeader = 0x100;

        const _ = !0;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u16))]
    pub struct BTreeNodeFlagsRaw: u16 {
        /// The B-tree node is a root node (`BTNODE_ROOT`).
        ///
        /// If set, the object type should be [ObjectType::BTreeRoot].
        ///
        /// If this is the tree's only node, both this flag and [Self::Leaf] are set.
        /// Otherwise, [Self::Leaf] cannot be set.
        const Root = 0x0001;

        /// The B-tree node is a leaf node (`BTNODE_LEAF`).
        ///
        /// If this is the tree's only node, the object type should be [ObjectType::BTreeRoot]
        /// and [Self::Root] should also be set.
        ///
        /// Otherwise the object type should be [PbjectType::BTreeNode].
        const Leaf = 0x0002;

        /// The B-tree node has keys and values of a fixed size (`BTNODE_FIXED_KVSIZE`).
        ///
        /// If the keys and values all have a static size this should be set.
        ///
        /// The sizes of the keys and values is recorded in the [BTreeInfoRaw] record
        /// in the root node.
        ///
        /// It is valid to have a mix of nodes within the same tree with varying values
        /// of this flag. For example, non-leaf nodes - whose keys and values are
        /// identifiers - can have it set but leaf nodes don't.
        const FixedKeyValueSize = 0x0004;

        /// The B-tree node contains child hashes (`BTNODE_HASHED`).
        ///
        /// This flag is only valid on B-trees having the [BTreeFlagsRaw::Hashed] flag set.
        ///
        /// Has no effect on leaf nodes.
        const Hashed = 0x0008;

        /// The B-tree node is stored without an object header (`BTNODE_NOHEADER`).
        ///
        /// This flag is valid only on B-trees having the [BTreeFlagsRaw::NoHeader] flag.
        ///
        /// If set, the [BTreeNodeRaw::object] field is 0.
        const NoHeader = 0x0010;

        /// The B-tree node is in a transient state (`BTNODE_CHECK_KOFF_INVAL`).
        ///
        /// Objects with this flag never appear on disk.
        const CheckKoffInval = 0x8000;
    }
}

/// A B-tree node (`btree_node_phys_t`).
///
/// Following this header is storage for the table of contents, keys
/// data, values data, and an optional trailer for root nodes.
///
/// The keys data begins after the table of contents and ends before the
/// start of the shared free space.
///
/// The values data begins after the end of the shared free space and
/// ends at the end of the node or before the [BTreeInfoRaw] struct, which
/// is at the end of root nodes.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct BTreeNodeRaw {
    /// Common object header (`btn_o`).
    pub object: ObjectHeaderRaw,

    /// Node flags (`btn_flags`).
    pub flags: BTreeNodeFlagsRaw,

    /// The number of child levels below this node (`btn_level`).
    ///
    /// Should be 0 for leaf nodes, 1 for the parent of a leaf node.
    ///
    /// Total tree height is this value from the root node + 1.
    pub level: u16,

    /// The number of keys stored in this node (`btn_nkeys`).
    pub number_keys: u32,

    /// The location of the table of contents (`btn_table_space`).
    ///
    /// The offset for the table of contents is counted from the beginning
    /// of the [Self::data] field.
    ///
    /// If [BTreeNodeFlagsRaw::FixedKeyValueSize] is set, the ToC is an array
    /// of [KeyValueOffsetRaw]. Else it is an array of [NodeLocationRaw].
    pub table_space: NodeLocationRaw,

    /// The location of the shared free space for keys and values (`btn_free_space`).
    ///
    /// Counted from the beginning of the key area to the beginning of the
    /// free space.
    pub free_space: NodeLocationRaw,

    /// A linked list that tracks free key space (`btn_key_free_list`).
    ///
    /// The `offset` field is the offset from the beginning of the key area to
    /// the first available space. The `length` field is the total amount of
    /// free key space in this segment.
    ///
    /// Each free space stores an instance of [NodeLocationRaw]. Each's
    /// `length` field contains the size of that free space and `offset` contains
    /// the next entry in the linked list.
    pub key_free_list: NodeLocationRaw,

    /// A linked list that tracks free value space (`btn_val_free_list`).
    ///
    /// Semantics are similar to [Self::key_free_list]. However, keep in
    /// mind that values are stored from back to front in the node.
    pub value_free_list: NodeLocationRaw,

    /// The node's data (`btn_data`).
    ///
    /// This contains the table of contents, keys, free space, values, and an
    /// optional [BTreeInfoRaw] for root nodes.
    ///
    /// Note: the Apple docs represent this as a u64 array because by default keys
    /// and values are 64-bit aligned. We choose to model as a byte array for
    /// consistency with other data structures.
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub data: [u8; 0],
}

impl DynamicSized for BTreeNodeRaw {
    // Data is aligned at the end of the block. So end offset is unknown
    // without knowing block size.
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}

/// Static information about a B-tree (`btree_info_fixed_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct BTreeInfoFixedRaw {
    /// The B-tree's flags (`bt_flags`).
    pub flags: BTreeFlagsRaw,

    /// The on-disk size, in bytes, of a node in this B-tree (`bt_node_size`).
    pub node_size: u32,

    /// The size of a key, or zero if the keys have variable size (`bt_key_size`).
    pub key_size: u32,

    /// The size of a value, or zero if the values have variable size (`bt_val_size`).
    pub value_size: u32,
}

impl BTreeInfoFixedRaw {
    /// Resolve the intra-tree node OID storage type in use by the tree.
    pub fn node_oid_storage(&self) -> StorageClass {
        if self.flags.contains(BTreeFlagsRaw::Physical) {
            StorageClass::Physical
        } else if self.flags.contains(BTreeFlagsRaw::Ephemeral) {
            StorageClass::Ephemeral
        } else {
            StorageClass::Virtual
        }
    }
}

/// Information about a B-tree (`btree_info_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct BTreeInfoRaw {
    /// Information about the B-tree that doesn't change over time (`bt_fixed`).
    pub fixed: BTreeInfoFixedRaw,

    /// The length, in bytes, of the longest key that has ever been stored in the B-tree (`bt_longest_key`).
    pub longest_key: u32,

    /// The length, in bytes, of the longest value that has ever been stored in the B-tree (`bt_longest_val`).
    pub longest_value: u32,

    /// The number of keys stored in the B-tree (`bt_key_count`).
    pub key_count: u64,

    /// The number of nodes stored in the B-tree (`bt_node_count`).
    pub node_count: u64,
}
