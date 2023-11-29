// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Space manager.
//!
//! The space manager is in charge of tracking allocated / free blocks at
//! the container level. There is one space manager per container.
//!
//! The main space manager data structure is [SpaceManagerBlockRaw]. The block
//! holding it is defined by [ContainerSuperblockRaw::space_manager_oid].
//!
//! # Internal Pool
//!
//! The space manager carves out space for its own record keeping named the
//! *internal pool*. This is a sequential span of blocks as pointed to by
//! [SpaceManagerBlockRaw::internal_pool_base] and
//! [SpaceManagerBlockRaw::internal_pool_block_count].
//!
//! The internal pool consists of:
//!
//! * [ChunkInfoBlockRaw]
//! * [ChunkInfoAddressesBlockRaw].
//! * Bitmaps used by [ChunkInfoBlockRaw].
//!
//! The size of the internal pool is derived from the block size of the
//! container:
//!
//! 1. There must be a bitmap bit for every container block.
//! 2. There must be a [ChunkInfoBlockRaw] describing each bitmap block.
//!
//! # Free Queue
//!
//! The space manager tracks lists of empty block ranges using a *free queue*.
//!
//! The free queues are backed by B-trees.

use crate::{
    common::{EphemeralObjectIdentifierRaw, PhysicalAddressRaw, TransactionIdentifierRaw},
    object::ObjectHeaderRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::cmp::Ordering;
use core::fmt::{Display, Formatter};
use core::ops::{Deref, Range, RangeFrom};

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

#[cfg(doc)]
use crate::{common::*, container::*, object::*};

/// Information about a bitmap chunk (`chunk_info_t`).
///
/// Instances point to a physical block holding a bitmap describing the
/// allocation status of a range of blocks.
///
/// Each bitmap describes a range of blocks from absolute address
/// [Self::address] to that value + [Self::block_count], non-inclusive.
///
/// If a bit in the bitmap is set, the corresponding block is in use.
/// If a bit is unset, the block is free/available.
///
/// There is an apparent optimization where the special case of
/// [Self::block_count] == [Self::free_count] can have
/// [Self::bitmap_address] = 0 to automagically represent the fully empty
/// bitmap. This avoids having to store/update bitmaps for empty block
/// ranges.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ChunkInfoRaw {
    /// Transaction identifier instance is associated with (`ci_xid`).
    pub transaction_id: u64,

    /// Starting block address being described (`ci_addr`).
    pub address: u64,

    /// The number of blocks / bits in the bitmap (`ci_block_count`).
    ///
    /// This should be 8 * block_size since each bitmap consumes the full block.
    pub block_count: u32,

    /// The number of available blocks / bits in the bitmap (`ci_free_count`).
    ///
    /// This expresses the count of unset bits.
    pub free_count: u32,

    /// Block number of a bitmap describing this chunk (`ci_bitmap_addr`).
    ///
    /// 0 value indicates a bitmap is not stored.
    pub bitmap_address: PhysicalAddressRaw,
}

/// A block containing [ChunkInfoRaw] structs (`chunk_info_block_t`).
///
/// Blocks are physically located inside the internal pool managed by
/// the space manager.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ChunkInfoBlockRaw {
    /// Common object header (`cib_o`).
    pub object: ObjectHeaderRaw,

    /// Index of this info block among all instances (`cib_index`).
    ///
    /// First info block should have index = 0.
    pub index: u32,

    /// Number of [ChunkInfoRaw] in the array following this field (`cib_chunk_info_count`).
    pub chunk_info_count: u32,

    /// (`cib_chunk_info`).
    ///
    /// Array of [ChunkInfoRaw] instances.
    #[cfg_attr(
        feature = "derive",
        apfs(trailing_data = "crate::pod::MemoryBackedArray<ChunkInfoRaw, ChunkInfoParsed>")
    )]
    pub data: [ChunkInfoRaw; 0],
}

impl DynamicSized for ChunkInfoBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        let size = self.chunk_info_count as usize * core::mem::size_of::<ChunkInfoRaw>();

        0..size
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for ChunkInfoBlockRaw {
    type TrailingData = crate::pod::MemoryBackedArray<ChunkInfoRaw, ChunkInfoParsed>;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::MemoryBackedArray::new(data, self.chunk_info_count as _)
    }
}

/// A block containing an array of [ChunkInfoBlockRaw] block addresses (`cib_addr_block_t`).
///
/// Blocks are physically located inside the internal pool managed by
// the space manager.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
pub struct ChunkInfoAddressesBlockRaw {
    /// Common object header (`cab_o`)
    pub object: ObjectHeaderRaw,

    /// Index of this block among all others of the same type (`cab_index`).
    pub index: u32,

    /// The number of items in the [Self::addresses] array (`cab_cib_count`).
    pub count: u32,

    /// Block addresses of [ChunkInfoBlockRaw] (`cab_cib_addr`).
    #[cfg_attr(
        feature = "derive",
        apfs(
            trailing_data = "crate::pod::MemoryBackedArray<PhysicalAddressRaw, crate::common::PhysicalAddressParsed>"
        )
    )]
    pub addresses: [PhysicalAddressRaw; 0],
}

impl DynamicSized for ChunkInfoAddressesBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        let size = self.count as usize * core::mem::size_of::<PhysicalAddressRaw>();

        0..size
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for ChunkInfoAddressesBlockRaw {
    type TrailingData =
        crate::pod::MemoryBackedArray<PhysicalAddressRaw, crate::common::PhysicalAddressParsed>;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::MemoryBackedArray::new(data, self.count as _)
    }
}

/// The number of space manager free queue types.
pub const SPACE_MANAGER_FREE_QUEUE_COUNT: usize = 3;

/// The type of a space manager free queue (`sfq`).
#[repr(usize)]
pub enum SpaceManagerFreeQueueType {
    /// Internal pool (`SFQ_IP`).
    InternalPool = 0,
    /// Main device (`MAIN`).
    Main = 1,
    /// Tier 2 device (fusion drive setups) (`SFQ_TIER2`).
    Tier2 = 2,
}

/// Space manager free queue (`spaceman_free_queue_t`).
///
/// This is a glorified reference to a B-tree holding free queue entries.
///
/// Keys in the B-tree are represented by [SpaceManagerFreeQueueKeyRaw].
///
/// Values in the B-tree are u64 count of blocks. Ghost keys are used to
/// represent the count=1 special case without having to store an explicit
/// value in the B-tree.
///
/// Essentially, the free queue represents a series of physical address
/// ranges tagged with transaction IDs.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerFreeQueueRaw {
    /// Total number of entries in the free queue (`sfq_count`).
    pub count: u64,

    /// Ephemeral ID of B-tree root containing free queue entries (`sfq_tree_oid`).
    ///
    /// Sub-type should be [ObjectType::SpaceManagerFreeQueue].
    pub tree_oid: EphemeralObjectIdentifierRaw,

    /// The oldest transaction ID referenced by the free queue (`sfq_oldest_xid`).
    pub oldest_xid: TransactionIdentifierRaw,

    /// (`sfq_tree_node_limit`).
    pub tree_node_limit: u16,
    /// (`sfq_pad16`).
    pub pad16: u16,
    /// (`sfq_pad32`).
    pub pad32: u32,
    /// (`sfq_reserved`).
    pub reserved: u64,
}

/// Space manager free queue key (`spaceman_free_queue_key_t`).
///
/// Represents keys in a B-tree of subtype [ObjectType::SpaceManagerFreeQueue].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerFreeQueueKeyRaw {
    /// Transaction identifier associated with the key (`sfqk_xid`).
    pub xid: TransactionIdentifierRaw,

    /// Block represented by the free queue entry (`sfqk_paddr`).
    pub address: PhysicalAddressRaw,
}

// Keys sorted by transaction identifier and then physical address.

impl Ord for SpaceManagerFreeQueueKeyRaw {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.xid, self.address).cmp(&(other.xid, other.address))
    }
}

impl PartialOrd for SpaceManagerFreeQueueKeyRaw {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Space manager free queue value.
///
/// Represents the number of blocks at a physical address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerFreeQueueValueRaw(pub u64);

impl Deref for SpaceManagerFreeQueueValueRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for SpaceManagerFreeQueueValueRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl From<SpaceManagerFreeQueueValueRaw> for u64 {
    fn from(value: SpaceManagerFreeQueueValueRaw) -> Self {
        value.0
    }
}

impl From<u64> for SpaceManagerFreeQueueValueRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Space manager free queue entry (`spaceman_free_queue_entry`).
///
/// Represents a logical entry in a free queue.
///
/// It is unknown if this type is stored on disk.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerFreeQueueEntryRaw {
    /// (`sfqe_key`)
    pub key: SpaceManagerFreeQueueKeyRaw,
    /// (`sfqe_count`)
    pub count: SpaceManagerFreeQueueValueRaw,
}

/// Space manager device (`spaceman_device_t`).
///
/// Describes a physical storage device and hows its blocks are used.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerDeviceRaw {
    /// The number of physical blocks provided by this device (`sm_block_count`).
    pub block_count: u64,

    /// The number of [ChunkInfoRaw] used to express this device's info (`sm_count_count`).
    ///
    /// Each [ChunkInfoRaw] block has block_size * 8 (bits) to express blocks. Or
    /// 32768 for the default of 4096 byte blocks. The number of chunks should
    /// be [Self::block_count] divided by the per-chunk block capacity then
    /// rounded up to the next whole number.
    pub chunk_count: u64,

    /// Total number of [ChunkInfoBlockRaw] addressed in this instance (`sm_cib_count`)
    ///
    /// See documentation for [Self::address_offset].
    pub chunk_info_block_count: u32,

    /// Total number of [ChunkInfoAddressesBlockRaw] addresses in this instance (`sm_cab_count`).
    ///
    /// See documentation for [Self::address_offset].
    pub chunk_info_address_block_count: u32,

    /// Total number of unallocated / free blocks in this device (`sm_free_count`).
    ///
    /// Should match the sum of free counts from all referenced [ChunkInfoRaw]
    /// instances.
    pub free_count: u64,

    /// Address offset from start of [SpaceManagerBlockRaw] holding chunk info addresses (`sm_addr_offset`).
    ///
    /// This points to an array of physical addresses (u64).
    ///
    /// If [Self::chunk_info_address_block_count] is non-0, the array is that
    /// many elements long and the physical blocks resolve to instances of
    /// [ChunkInfoAddressesBlockRaw].
    ///
    /// Else if [Self::chunk_info_block_count] is non-0, the array is that many
    /// elements long and consists of inline physical addresses, without the
    /// [ChunkInfoAddressesBlockRaw] abstraction.
    ///
    /// Either way, this effectively resolves to a list of physical addresses
    /// which resolve to [ChunkInfoBlockRaw] instances. The total number of resolved
    /// addresses should be [Self::chunk_info_block_count].
    pub address_offset: u32,

    /// (`sm_reserved`)
    pub reserved: u32,
    /// (`sm_reserved2`)
    pub reserved2: u32,
}

/// (`spaceman_allocation_zone_boundaries_t`)
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerAllocationZoneBoundariesRaw {
    /// (`saz_zone_start`)
    pub zone_start: u64,
    /// (`saz_zone_end`)
    pub zone_end: u64,
}

/// (`spaceman_allocation_zone_info_phys_t`)
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerAllocationZoneInfoRaw {
    /// (`saz_current_boundaries`)
    pub current_boundaries: SpaceManagerAllocationZoneBoundariesRaw,
    /// (`saz_previous_boundaries`)
    pub previous_boundaries: [SpaceManagerAllocationZoneBoundariesRaw; 7],
    /// (`saz_zone_id`)
    pub zone_id: u16,
    /// (`saz_previous_boundary_index`)
    pub previous_boundary_index: u16,
    /// (`saz_reserved`)
    pub reserved: u32,
}

/// Type alias for allocation zone matrix.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
pub struct SpaceManagerAllocationZonesRaw(pub [SpaceManagerAllocationZoneInfoRaw; 8]);

impl Deref for SpaceManagerAllocationZonesRaw {
    type Target = [SpaceManagerAllocationZoneInfoRaw; 8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Space manager device type IDs (`smdev`).
///
/// Used as indices into [SpaceManagerBlockRaw::devices].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(usize)]
pub enum SpaceManagerDeviceType {
    /// (`SD_MAIN`)
    Main = 0,
    /// (`SD_TIER2`)
    Tier2 = 1,
}

/// The number of distinct space manager device types (`SD_COUNT`).
pub const SPACE_MANAGER_DEVICE_COUNT: usize = 2;

/// (`spaceman_datazone_info_phys_t`)
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerDatazoneInfoRaw {
    /// (`sdz_allocation_zones`)
    pub allocation_zones: [SpaceManagerAllocationZonesRaw; SPACE_MANAGER_DEVICE_COUNT],
}

bitflags! {
    /// Space manager flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct SpaceManagerFlagsRaw: u32 {
        const Versioned = 0x01;
    }
}

/// (`APFS_SPACEMAN_IP_BM_TX_MULTIPLIER`).
pub const INTERNAL_POOL_BITMAP_TX_MULTIPLIER: u32 = 16;

/// Represents an invalid index in a bitmap index/offsets entry (`SPACEMAN_IP_BM_INDEX_INVALID`).
pub const INTERNAL_POOL_BITMAP_INDEX_INVALID: u16 = 0xffff;

/// Space manager block (`spaceman_phys_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct SpaceManagerBlockRaw {
    /// Common object header (`sm_o`).
    pub object: ObjectHeaderRaw,

    /// Size of container blocks, in bytes (`sm_block_size`).
    ///
    /// Should match [ContainerSuperblockRaw::block_size_bytes].
    pub block_size_bytes: u32,

    /// The number of blocks described by each chunk info block (`sm_blocks_per_chunk`).
    ///
    /// Should be 8 * [Self::block_size_bytes].
    pub blocks_per_chunk: u32,

    /// The number of [ChunkInfoRaw] that can be stored in a [ChunkInfoBlockRaw] (`sm_chunks_per_cib`).
    ///
    /// This is the maximum number of [ChunkInfoRaw] instances that can be stored in
    /// the array at the end of [ChunkInfoBlockRaw]. This is derived from the block
    /// size in use.
    ///
    /// For 4096 byte blocks, this is 126.
    pub chunks_per_info_block: u32,

    /// The maximum number of addresses that can be stored in a [ChunkInfoAddressesBlockRaw] (`sm_cibs_per_cab`).
    ///
    /// This is the maximum size of the [ChunkInfoAddressesBlockRaw::addresses] array that
    /// can fit in the block size.
    ///
    /// For 4096 byte blocks, this is 507.
    pub info_blocks_per_chunk_address_blocks: u32,

    /// Describes space info for each device (`sm_dev`).
    ///
    /// Indices are logically [SpaceManagerDeviceType]. First device is
    /// the main device. Second is the *tier 2* slower device. Second device
    /// is only present when in fusion mode.
    ///
    /// Each instance describes blocks allocated for each respective device,
    /// including where to find the bitmaps indicating allocation state of
    /// each block.
    pub devices: [SpaceManagerDeviceRaw; SPACE_MANAGER_DEVICE_COUNT],

    /// Flags for this data structure (`sm_flags`).
    pub flags: SpaceManagerFlagsRaw,

    /// (`sm_ip_bm_tx_multiplier`).
    ///
    /// Seems to match the [INTERNAL_POOL_BITMAP_TX_MULTIPLIER] constant.
    pub internal_pool_bitmap_tx_multipler: u32,

    /// Internal pool block count (`sm_ip_block_count`).
    ///
    /// Number of blocks for the internal pool.
    pub internal_pool_block_count: u64,

    /// Size of internal pool bitmaps in blocks (`sm_ip_bm_size_in_blocks`).
    ///
    /// The IP bitmap can span multiple blocks.
    pub internal_pool_bitmap_size_in_blocks: u32,

    /// Number of blocks in the internal pool bitmap ring buffer (`sm_ip_bm_block_count`).
    pub internal_pool_bitmap_block_count: u32,

    /// First block of the internal pool bitmap ring buffer (`sm_ip_bm_base`).
    ///
    /// There are [Self::internal_pool_bitmap_block_count] blocks in this range.
    pub internal_pool_bitmap_base: PhysicalAddressRaw,

    /// First block of the internal pool [ChunkInfoBlockRaw] instances (`sm_ip_base`).
    ///
    /// Blocks are [ChunkInfoBlockRaw] as well as their bitmaps.
    pub internal_pool_base: PhysicalAddressRaw,

    /// (`sm_fs_reserve_block_count`)
    pub fs_reserve_block_count: u64,
    /// (`sm_fs_reserve_alloc_count`)
    pub fs_reserve_alloc_count: u64,
    /// Free queues (`sm_fq`).
    ///
    /// Indices are represented by [SpaceManagerFreeQueueType].
    pub free_queue: [SpaceManagerFreeQueueRaw; SPACE_MANAGER_FREE_QUEUE_COUNT],

    /// Next available IP bitmap offset (`sm_ip_bm_free_head`).
    ///
    /// Stores the offset from [Self::internal_pool_bitmap_base] holding the
    /// next free block in the internal pool bitmap ring buffer.
    ///
    /// e.g. if [Self::internal_pool_bitmap_offset] resolves to 3 and
    /// [Self::internal_pool_bitmap_size_in_blocks] is 1, this would be 4.
    ///
    /// Since the internal pool is a ring buffer, the next available offset
    /// could wrap around to 0 at [Self::internal_pool_bitmap_block_count].
    pub internal_pool_bitmap_free_head: u16,

    /// Last available IP bitmap offset (`sm_ip_bm_free_tail`).
    ///
    /// Stores the offset from [Self::internal_pool_bitmap_base] holding the
    /// last free block in the internal pool bitmap ring buffer.
    ///
    /// e.g. if [Self::internal_pool_bitmap_offset] resolves to 3 and
    /// [Self::internal_pool_bitmap_size_in_blocks] is 1, this would be 2.
    pub internal_pool_bitmap_free_tail: u16,

    /// Offset to transaction identifier for internal pool bitmap (`sm_ip_bm_xid_offset`).
    ///
    /// Value is relative to beginning of this structure. Value is an u64 /
    /// [TransactionIdentifierRaw].
    pub internal_pool_bitmap_xid_offset: u32,

    /// Offset to index of internal pool bitmap in the ring buffer (`sm_ip_bitmap_offset`).
    ///
    /// The value recorded here is a byte offset from the start of this data
    /// structure. The target bytes are a u64 holding the offset relative to
    /// [Self::internal_pool_bitmap_base]. The result of summing these values is the
    /// physical / block address of the internal pool bitmap.
    pub internal_pool_bitmap_offset: u32,

    /// Offset to an array holding offsets in the internal pool bitmap ring buffer (`sm_ip_bm_free_next_offset`).
    ///
    /// The value recorded is a byte offset from the start of this data structure.
    /// The target offset contains an array of u16 of length [Self::internal_pool_bitmap_block_count].
    /// Each value in the array seems to represent the internal pool bitmap index
    /// for the next free offset in the ring buffer. Values of 0xffff /
    /// [INTERNAL_POOL_BITMAP_INDEX_INVALID] represent invalid indices. e.g.
    /// slots in the ring buffer that are occupied.
    ///
    /// The values recorded for [Self::internal_pool_bitmap_size_in_blocks] == 1
    /// ring buffers is `<index> + 1` for all indices except
    /// [Self::internal_pool_bitmap_offset] and the one before it.
    pub internal_pool_bitmap_free_next_offset: u32,

    /// Version of this data structure (`sm_version`).
    ///
    /// Only version `1` is known.
    pub version: u32,

    /// Size of this data structure (`sm_struct_size`).
    ///
    /// Seems to include the contents of [Self::datazone].
    ///
    /// Seems to be identical to [Self::internal_pool_bitmap_xid_offset],
    /// implying that IP bitmap XID is stored immediately after this struct.
    pub struct_size: u32,

    /// (`sm_datazone`)
    pub datazone: SpaceManagerDatazoneInfoRaw,

    /// Extra data.
    ///
    /// Chunk info address references are here.
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub extra: [u8; 0],
}

// The chunk info address references follow the data structure. So we need
// to preserve all block data.
impl DynamicSized for SpaceManagerBlockRaw {
    type RangeBounds = RangeFrom<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..
    }
}
