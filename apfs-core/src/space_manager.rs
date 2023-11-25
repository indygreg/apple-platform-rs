// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::block::{Block, BlockReader};
use crate::btree::BTree;
use crate::error::{ApfsError, Result};
use crate::read::container::SuperblockReader;
use apfs_types::common::{
    PhysicalAddressRaw, PhysicalObjectIdentifierRaw, TransactionIdentifierRaw,
};
pub use apfs_types::space_manager::*;
use apfs_types::{DiskStruct, ParsedDiskStruct};
use bit_vec::BitVec;
use bytes::Bytes;
use std::ops::Deref;

/// Represents a bitmap referenced by a [ChunkInfoRaw].
///
/// Instances are constructed from block bytes referenced by a [ChunkInfoRaw]
/// instance. Each bit in the bitmap indicates whether the corresponding
/// block number is in use.
pub struct SpaceManagerChunkBitmap {
    info: ChunkInfoRaw,
    bitmap: BitVec,
}

impl SpaceManagerChunkBitmap {
    /// Construct an instance from a bytes slice.
    pub fn new(info: &ChunkInfoRaw, data: &[u8]) -> Self {
        let info = *info;
        let bitmap = BitVec::from_bytes(data);

        Self { info, bitmap }
    }

    /// The starting block number of this bitmap.
    pub fn starting_address(&self) -> PhysicalAddressRaw {
        (self.info.address() as i64).into()
    }

    /// The final block number stored in this bitmap.
    pub fn ending_address(&self) -> PhysicalAddressRaw {
        self.starting_address() + self.info.block_count() - 1
    }

    /// Obtain all block addresses described by this bitmap.
    pub fn block_addresses(&self) -> impl Iterator<Item = PhysicalAddressRaw> {
        // Step isn't implemented for PhysicalAddress. So do the range in domain
        // of ints and cast to get emitted value.
        (i64::from(self.starting_address())..=i64::from(self.ending_address()))
            .map(PhysicalAddressRaw::from)
    }

    /// Get the set status of a bit.
    ///
    /// The index is the relative block number.
    pub fn get_relative(&self, i: usize) -> Option<bool> {
        if i < self.info.block_count() as _ {
            self.bitmap.get(i)
        } else {
            None
        }
    }

    /// Get the set status of a block.
    pub fn get_block(&self, addr: PhysicalAddressRaw) -> Option<bool> {
        if addr < self.starting_address() || addr > self.ending_address() {
            None
        } else {
            let rel = addr - self.starting_address();

            self.bitmap.get(rel.into())
        }
    }

    /// Iterate the block addresses and bits in this instance.
    pub fn iter_bits(&self) -> impl Iterator<Item = (PhysicalAddressRaw, bool)> + '_ {
        self.block_addresses().map(|addr| {
            let rel = addr - self.starting_address();

            let v = self
                .bitmap
                .get(rel.into())
                .expect("bit should be within range");

            (addr, v)
        })
    }
}

#[derive(Clone)]
pub struct SpaceManagerBlock {
    block_number: PhysicalObjectIdentifierRaw,
    sm: SpaceManagerBlockParsed,
}

impl Deref for SpaceManagerBlock {
    type Target = SpaceManagerBlockParsed;

    fn deref(&self) -> &Self::Target {
        &self.sm
    }
}

impl SpaceManagerBlock {
    pub fn new(block: Block) -> Result<Self> {
        let sm = SpaceManagerBlockParsed::from_bytes(block.bytes())?;

        Ok(Self {
            block_number: block.number(),
            sm,
        })
    }

    pub fn block_number(&self) -> PhysicalObjectIdentifierRaw {
        self.block_number
    }

    pub fn space_manager(&self) -> &SpaceManagerBlockParsed {
        &self.sm
    }

    /// Obtain data slice backing chunk chunk info data/addresses.
    pub fn chunk_info_block_data(&self, device: SpaceManagerDeviceType) -> Result<Bytes> {
        let device = &self.devices()[device as usize];

        Ok(self.bytes().slice(device.address_offset() as usize..))
    }

    /// Obtain the physical addresses of [ChunkInfoAddressesBlock] instances.
    pub fn chunk_info_address_block_ids(
        &self,
        device_type: SpaceManagerDeviceType,
    ) -> Result<Vec<PhysicalAddressRaw>> {
        let device = &self.devices()[device_type as usize];

        let mut res = Vec::with_capacity(device.chunk_info_address_block_count() as _);

        let address = self.chunk_info_block_data(device_type)?;
        let mut offset = 0;

        for _ in 0..device.chunk_info_address_block_count() {
            let oid = i64::parse_bytes(&address.as_ref()[offset..])?;
            offset += 8;

            res.push(oid.into());
        }

        Ok(res)
    }

    /// Obtain inline physical address of [ChunkInfoBlock] instances.
    pub fn chunk_info_block_ids(
        &self,
        device_type: SpaceManagerDeviceType,
    ) -> Result<Vec<PhysicalAddressRaw>> {
        let device = &self.devices()[device_type as usize];

        let mut res = Vec::with_capacity(device.chunk_info_block_count() as usize);

        let address = self.chunk_info_block_data(device_type)?;
        let mut offset = 0;

        for _ in 0..device.chunk_info_block_count() {
            let oid = i64::parse_bytes(&address.as_ref()[offset..])?;
            offset += 8;
            res.push(oid.into());
        }

        Ok(res)
    }

    /// Internal pool bitmap transaction identifier.
    pub fn internal_pool_bitmap_xid(&self) -> Result<TransactionIdentifierRaw> {
        let offset = self.internal_pool_bitmap_xid_offset() as usize;
        let xid = u64::parse_bytes(&self.bytes().as_ref()[offset..])?;

        Ok(xid.into())
    }

    /// Compute the offset to the internal pool bitmap.
    ///
    /// Returned value is relative to [crate::space_manager::SpaceManagerBlockRaw::internal_pool_bitmap_base].
    pub fn internal_pool_bitmap_offset(&self) -> Result<u64> {
        let offset = SpaceManagerBlockRaw::internal_pool_bitmap_offset(self) as usize;

        Ok(u64::parse_bytes(&self.bytes().as_ref()[offset..])?)
    }

    /// Resolve the internal pool bitmap block.
    pub fn internal_pool_bitmap_block(&self) -> Result<PhysicalAddressRaw> {
        Ok(self.internal_pool_bitmap_base() + self.internal_pool_bitmap_offset()?)
    }

    /// Determine whether an index in the internal pool bitmap ring buffer is occupied.
    ///
    /// Passed value is a 0-relative index within the ring buffer, not a block number.
    pub fn internal_pool_bitmap_is_occupied(&self, i: usize) -> crate::error::Result<bool> {
        let block_count = self.internal_pool_bitmap_block_count() as usize;
        let current_offset = self.internal_pool_bitmap_offset()? as usize;
        Ok(
            (current_offset..current_offset + self.internal_pool_bitmap_size_in_blocks() as usize)
                .map(|v| v % block_count)
                .any(|v| v == i),
        )
    }

    /// Resolve the internal pool bitmap ring buffer next free offsets mapping.
    ///
    /// Values can be [INTERNAL_POOL_BITMAP_INDEX_INVALID].
    pub fn internal_pool_bitmap_free_next_offsets(&self) -> Result<Vec<u16>> {
        let mut res = Vec::with_capacity(self.internal_pool_bitmap_block_count() as _);

        let mut offset = self.internal_pool_bitmap_free_next_offset() as usize;
        for _ in 0..self.internal_pool_bitmap_block_count() {
            res.push(u16::parse_bytes(&self.bytes().as_ref()[offset..])?);
            offset += 2;
        }

        Ok(res)
    }

    /// Obtain a free queue b-tree for the specified queue.
    pub fn free_queue(
        &self,
        reader: &SuperblockReader,
        queue: SpaceManagerFreeQueueType,
    ) -> Result<Option<BTree>> {
        let queue = &self.sm.free_queue()[queue as usize];

        if queue.tree_oid() != 0.into() {
            let mapping = reader
                .find_ephemeral_object_mapping(queue.tree_oid())
                .ok_or_else(|| ApfsError::EphemeralObjectNotFound(queue.tree_oid()))?;

            let block = reader.get_block_validated(mapping.address())?;
            Ok(Some(BTree::from_block(block)?))
        } else {
            Ok(None)
        }
    }

    /// Walk the specified free queue.
    pub fn walk_free_queue(
        &self,
        reader: &SuperblockReader,
        queue: SpaceManagerFreeQueueType,
        cb: impl Fn(SpaceManagerFreeQueueKeyParsed, SpaceManagerFreeQueueValueRaw) -> Result<()>,
    ) -> Result<()> {
        if let Some(queue) = self.free_queue(reader, queue)? {
            for res in queue.iter_entries(reader, &reader.object_map()?) {
                let (k, v) = res?;

                let k = SpaceManagerFreeQueueKeyParsed::from_bytes(k.into())?;

                // Ghost entries represent length = 1.
                let v = SpaceManagerFreeQueueValueRaw::from(if v.is_empty() {
                    1
                } else {
                    u64::parse_bytes(v.as_ref())?
                });

                cb(k, v)?;
            }
        }

        Ok(())
    }

    /// Obtain the blocks holding space manager chunk info.
    pub fn resolve_chunk_info_block_ids(
        &self,
        reader: &impl BlockReader,
        device_type: SpaceManagerDeviceType,
    ) -> Result<Vec<PhysicalAddressRaw>> {
        let device = &self.devices()[device_type as usize];

        let mut res = Vec::with_capacity(device.chunk_info_block_count() as _);

        if device.chunk_info_address_block_count() > 0 {
            for addr in self.chunk_info_address_block_ids(device_type)? {
                let block = reader.get_block_validated(addr)?;
                let cab = ChunkInfoAddressesBlockParsed::from_bytes(block.bytes())?;

                for oid in cab.trailing_data()?.iter() {
                    res.push(oid?.clone_inner());
                }
            }
        } else {
            for oid in self.chunk_info_block_ids(device_type)? {
                res.push(oid);
            }
        }

        Ok(res)
    }

    /// Iterate over resolved chunk info blocks for a device.
    pub fn iter_chunk_info_blocks<'a>(
        &'a self,
        reader: &'a impl BlockReader,
        device_type: SpaceManagerDeviceType,
    ) -> Result<impl Iterator<Item = Result<(PhysicalAddressRaw, ChunkInfoBlockParsed)>> + 'a> {
        Ok(self
            .resolve_chunk_info_block_ids(reader, device_type)?
            .into_iter()
            .map(|oid| {
                let block = reader.get_block_validated(oid)?;
                let cib = ChunkInfoBlockParsed::from_bytes(block.bytes())?;
                Ok((oid, cib))
            }))
    }
}
