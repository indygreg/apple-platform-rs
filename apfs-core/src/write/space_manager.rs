// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Space manager mutation.

use crate::block::{Block, BlockReader};
use crate::space_manager::{Result, SpaceManagerBlock, SpaceManagerError};
use crate::write::block::MutBlock;
use apfs_types::common::{
    ObjectIdentifierRaw, PhysicalAddressRaw, PhysicalObjectIdentifierRaw, TransactionIdentifierRaw,
};
use apfs_types::object::{ObjectType, ObjectTypeFlags, ObjectTypeValueRaw};
use apfs_types::space_manager::{
    ChunkInfoAddressesBlockRaw, ChunkInfoBlockRaw, ChunkInfoRaw, SpaceManagerBlockRaw,
    SpaceManagerDeviceType, SpaceManagerFlagsRaw, SpaceManagerFreeQueueType,
    INTERNAL_POOL_BITMAP_INDEX_INVALID, INTERNAL_POOL_BITMAP_TX_MULTIPLIER,
};
use apfs_types::DiskStruct;
use bit_vec::BitVec;
use std::io::Write;

/// Describes a segment of a bitmap.
pub struct BitmapChunk {
    info: ChunkInfoRaw,
    bitmap: Option<BitVec>,
}

impl BitmapChunk {
    /// Construct an instance from a [ChunkInfoRaw] and a block reader.
    pub fn from_reader(info: ChunkInfoRaw, reader: &impl BlockReader) -> Result<Self> {
        let bitmap = if info.bitmap_address() != 0i64.into() {
            let block = reader.get_block(info.bitmap_address())?;
            let v = BitVec::from_bytes(block.as_ref());
            Some(v)
        } else {
            None
        };

        Ok(Self { info, bitmap })
    }

    /// The starting block number of this segment.
    pub fn starting_address(&self) -> PhysicalAddressRaw {
        self.info.address().into()
    }

    /// The last block number tracked by this segment.
    pub fn last_address(&self) -> PhysicalAddressRaw {
        self.starting_address() + self.info.block_count() - 1
    }

    /// Obtain all block addresses described by this segment.
    pub fn block_addresses(&self) -> impl Iterator<Item = PhysicalAddressRaw> {
        (i64::from(self.starting_address())..=i64::from(self.last_address()))
            .map(PhysicalAddressRaw::from)
    }

    /// Get the set status of a bit.
    ///
    /// Index is relative to the starting block number.
    pub fn get_relative(&self, i: usize) -> Option<bool> {
        if i < self.info.block_count() as _ {
            if let Some(bm) = &self.bitmap {
                bm.get(i)
            } else if self.info.free_count() == self.info.block_count() {
                Some(false)
            } else if self.info.free_count() == 0 {
                Some(true)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the set status of a block, specified by its address.
    pub fn get_block(&self, addr: PhysicalAddressRaw) -> Option<bool> {
        if addr < self.starting_address() || addr > self.last_address() {
            None
        } else {
            let rel = addr - self.starting_address();

            if let Some(bm) = &self.bitmap {
                bm.get(rel.into())
            } else if self.info.free_count() == self.info.block_count() {
                Some(false)
            } else if self.info.free_count() == 0 {
                Some(true)
            } else {
                None
            }
        }
    }

    /// Ensure a bitvec is present.
    fn ensure_bitvec(&mut self) {
        if self.bitmap.is_none() {
            let data = vec![0u8; self.info.block_count().div_ceil(8) as usize];
            self.bitmap = Some(BitVec::from_bytes(&data));
        }
    }

    /// Ensure a provided address is within range of this segment, resolving the relative index.
    fn ensure_range(&self, addr: PhysicalAddressRaw) -> Result<usize> {
        if addr < self.starting_address() || addr > self.last_address() {
            Err(SpaceManagerError::BitmapBlockOutOfRange)
        } else {
            Ok(usize::from(addr - self.starting_address()))
        }
    }

    /// Set all blocks as occupied.
    pub fn set_all(&mut self) {
        self.info.set_free_count(0);
        self.bitmap = None;
    }

    /// Set all blocks as empty.
    pub fn unset_all(&mut self) {
        self.info.set_free_count(self.info.block_count());
        self.bitmap = None;
    }

    /// Mark a block as occupied.
    pub fn set_block(&mut self, addr: PhysicalAddressRaw) -> Result<()> {
        let rel = self.ensure_range(addr)?;
        self.ensure_bitvec();

        self.bitmap.as_mut().expect("bitvec present").set(rel, true);

        Ok(())
    }

    /// Mark a block as unused.
    pub fn unset_block(&mut self, addr: PhysicalAddressRaw) -> Result<()> {
        let rel = self.ensure_range(addr)?;
        self.ensure_bitvec();

        self.bitmap
            .as_mut()
            .expect("bitvec present")
            .set(rel, false);

        Ok(())
    }
}

/// Represents a bitmap for a container.
///
/// This structure fully describes the bitmaps in the internal pool describing the
/// container level occupied blocks.
///
/// This does NOT represent the bitmap for the internal pool itself.
pub struct ContainerBitmap {
    /// The underlying chunks.
    chunks: Vec<BitmapChunk>,
    transaction_id: TransactionIdentifierRaw,
}

impl ContainerBitmap {
    /// Construct an empty bitmap for the specified transaction ID for a total number of blocks.
    pub fn empty(
        transaction_id: TransactionIdentifierRaw,
        block_size: usize,
        total_blocks: u64,
    ) -> Self {
        let blocks_per_chunk = 8 * block_size;
        let len = total_blocks.div_ceil(blocks_per_chunk as u64) as usize;

        let mut chunks = Vec::with_capacity(len);

        for index in 0..len {
            let address = (index * blocks_per_chunk) as u64;
            let block_count = if index == len - 1 {
                block_size - ((len * blocks_per_chunk) % total_blocks as usize)
            } else {
                block_size
            };

            let mut ci = ChunkInfoRaw::new_zeroed();
            ci.set_transaction_id(transaction_id.into());
            ci.set_address(address);
            ci.set_block_count(block_count as _);
            ci.set_free_count(ci.block_count());
            // 0 indicates a bitmap is not stored. Since free_count == block_count, storage
            // can be ellided.
            ci.set_bitmap_address(0i64.into());

            chunks.push(BitmapChunk {
                info: ci,
                bitmap: None,
            });
        }

        Self {
            chunks,
            transaction_id,
        }
    }

    /// The starting block number of this collection.
    pub fn starting_address(&self) -> PhysicalAddressRaw {
        self.chunks
            .first()
            .expect("should have at least 1 chunk")
            .starting_address()
    }

    /// The last address tracked by this collection.
    pub fn last_address(&self) -> PhysicalAddressRaw {
        self.chunks
            .last()
            .expect("should have at least 1 chunk")
            .last_address()
    }

    /// Obtain all block addresses described by this bitmap.
    pub fn block_addresses(&self) -> impl Iterator<Item = PhysicalAddressRaw> {
        (i64::from(self.starting_address())..=i64::from(self.last_address()))
            .map(PhysicalAddressRaw::from)
    }

    /// Find the chunk holding state for the specified address.
    fn find_chunk(&self, addr: PhysicalAddressRaw) -> Option<&BitmapChunk> {
        // TODO since chunks are sorted we could presumably jump direct to an index.
        self.chunks
            .iter()
            .find(|chunk| addr > chunk.starting_address() && addr <= chunk.last_address())
    }

    /// Find the chunk holding state for the specified address, returning a mutable reference.
    fn find_chunk_mut(&mut self, addr: PhysicalAddressRaw) -> Option<&mut BitmapChunk> {
        self.chunks
            .iter_mut()
            .find(|chunk| addr > chunk.starting_address() && addr <= chunk.last_address())
    }

    /// Determine whether a specified block number is occupied.
    pub fn get_block(&self, addr: PhysicalAddressRaw) -> Result<Option<bool>> {
        let chunk = self
            .find_chunk(addr)
            .ok_or(SpaceManagerError::BitmapBlockOutOfRange)?;
        Ok(chunk.get_block(addr))
    }

    /// Set a specified block number as used.
    pub fn set_block(&mut self, addr: impl Into<PhysicalAddressRaw>) -> Result<()> {
        let addr = addr.into();
        let xid = self.transaction_id;
        let chunk = self
            .find_chunk_mut(addr)
            .ok_or(SpaceManagerError::BitmapBlockOutOfRange)?;
        chunk.info.set_transaction_id(xid.into());
        chunk.set_block(addr)
    }

    /// Mark a specified block as unused.
    pub fn unset_block(&mut self, addr: impl Into<PhysicalAddressRaw>) -> Result<()> {
        let addr = addr.into();
        let xid = self.transaction_id;
        let chunk = self
            .find_chunk_mut(addr)
            .ok_or(SpaceManagerError::BitmapBlockOutOfRange)?;
        chunk.info.set_transaction_id(xid.into());
        chunk.unset_block(addr)
    }
}

/// Entity to create chunk info blocks.
///
/// These are blocks with a [ChunkInfoBlockRaw] header and an array of
/// [ChunkInfoRaw] defining bitmap metadata.
pub struct ChunkInfoBlockBuilder {
    block_size: usize,
    index: u32,
    entries: Vec<ChunkInfoRaw>,
}

impl ChunkInfoBlockBuilder {
    /// Construct an instance from a given block size in bytes and index of this instance.
    pub fn new(block_size: usize, index: u32) -> Self {
        Self {
            block_size,
            index,
            entries: vec![],
        }
    }

    /// The maximum number of entries that can be stored given the current block size.
    pub fn max_entries(&self) -> usize {
        (self.block_size - core::mem::size_of::<ChunkInfoBlockRaw>())
            / core::mem::size_of::<ChunkInfoRaw>()
    }

    /// Add a chunk info entry.
    pub fn push(&mut self, entry: ChunkInfoRaw) -> Result<()> {
        self.validate_size()?;
        self.entries.push(entry);
        Ok(())
    }

    /// Add a series of chunk info entries.
    pub fn extend(&mut self, entries: impl Iterator<Item = ChunkInfoRaw>) -> Result<()> {
        for entry in entries {
            self.push(entry)?;
        }
        Ok(())
    }

    fn validate_size(&self) -> Result<()> {
        if self.entries.len() >= self.max_entries() {
            Err(SpaceManagerError::ChunkInfoTooLarge)
        } else {
            Ok(())
        }
    }

    /// Build a [Block] from self.
    pub fn build(
        &self,
        block_number: impl Into<PhysicalObjectIdentifierRaw>,
        transaction_id: impl Into<TransactionIdentifierRaw>,
    ) -> Block {
        let block_number = block_number.into();
        let mut cib = ChunkInfoBlockRaw::new_zeroed();

        {
            let o = cib.object_mut();
            o.set_identifier(block_number.into());
            o.set_transaction_identifier(transaction_id.into());
            o.set_typ(ObjectTypeValueRaw::from_type_and_flags(
                ObjectType::SpaceManagerChunkInformationBlock,
                ObjectTypeFlags::Physical,
            ));
        }

        cib.set_index(self.index);
        cib.set_chunk_info_count(self.entries.len() as _);

        let mut block = MutBlock::new_zeroed(block_number, self.block_size);

        let header = &mut block.as_mut()[0..core::mem::size_of_val(&cib)];
        header.copy_from_slice(cib.as_bytes());

        for (index, entry) in self.entries.iter().enumerate() {
            let start = core::mem::size_of_val(&cib) + index * core::mem::size_of_val(entry);
            let end = start + core::mem::size_of_val(entry);

            let dest = &mut block.as_mut()[start..end];
            dest.copy_from_slice(entry.as_bytes());
        }

        block.checksum_and_freeze()
    }
}

/// Manages the state of the internal pool.
///
/// The internal pool is a ring buffer.
pub struct InternalPoolManager {
    sm: SpaceManagerBlockRaw,
    bitmap_xid: TransactionIdentifierRaw,
    bitmap_offset: u64,
    bitmap_free_next_offsets: Vec<u16>,
    chunk_info_addresses_main: Vec<PhysicalAddressRaw>,
    bitmap_blocks: Vec<MutBlock>,
    container_bitmap: ContainerBitmap,
}

impl InternalPoolManager {
    /// Construct a new instance for a new, empty container.
    ///
    /// Fusion / tier2 devices not yet supported.
    pub fn new_empty_container(
        block_size: usize,
        block_count: u64,
        oid: ObjectIdentifierRaw,
        initial_block: PhysicalAddressRaw,
    ) -> Result<Self> {
        // We emulate Apple's layout for the data after the struct.
        let bitmap_xid_offset = core::mem::size_of::<SpaceManagerBlockRaw>();
        assert_eq!(bitmap_xid_offset, 2520);
        let bitmap_offset = bitmap_xid_offset + 8;
        assert_eq!(bitmap_offset, 2528);
        // This array is variable size so this is as far as we can go with offset
        // calculation right now.
        let bitmap_free_next_offset = bitmap_offset + 8;
        assert_eq!(bitmap_free_next_offset, 2536);

        let mut sm = SpaceManagerBlockRaw::new_zeroed();
        {
            let o = sm.object_mut();
            o.set_identifier(oid);
            o.set_transaction_identifier(1.into());
            o.set_typ(ObjectTypeValueRaw::from_type_and_flags(
                ObjectType::SpaceManagerHeader,
                ObjectTypeFlags::Ephemeral,
            ));
        }

        sm.set_block_size_bytes(block_size as _);
        sm.set_blocks_per_chunk(8 * block_size as u32);

        // Maximum number of ChunkInfoRaw in the array at the end of ChunkInfoBlockRaw.
        sm.set_chunks_per_info_block(
            ((block_size - core::mem::size_of::<ChunkInfoBlockRaw>())
                / core::mem::size_of::<ChunkInfoRaw>()) as u32,
        );
        if block_size == 4096 {
            assert_eq!(sm.chunks_per_info_block(), 126);
        }

        // Maximum size of the ChunkInfoAddressesBlockRaw::addresses array.
        sm.set_info_blocks_per_chunk_address_blocks(
            ((block_size - core::mem::size_of::<ChunkInfoAddressesBlockRaw>())
                / core::mem::size_of::<PhysicalAddressRaw>()) as u32,
        );
        if block_size == 4096 {
            assert_eq!(sm.info_blocks_per_chunk_address_blocks(), 507);
        }

        // devices handled below.

        sm.set_flags(SpaceManagerFlagsRaw::Versioned);

        sm.set_internal_pool_bitmap_tx_multiplier(INTERNAL_POOL_BITMAP_TX_MULTIPLIER);

        let chunk_count = block_count.div_ceil(sm.blocks_per_chunk() as u64);
        let chunk_info_block_count = chunk_count.div_ceil(sm.chunks_per_info_block() as u64);

        // If there are few enough chunk info blocks, their addresses can be stored
        // inline in the space manager header. Otherwise, we need to spill out into the
        // info addresses block abstraction.
        // TODO do proper math

        let chunk_info_addresses_block_count = if chunk_info_block_count > 1 {
            chunk_info_block_count.div_ceil(sm.info_blocks_per_chunk_address_blocks() as u64)
        } else {
            0
        };

        // Apple appears to store 3 copies of the internal pool bitmaps. We follow their lead.
        let ip_block_count =
            (chunk_count + chunk_info_block_count + chunk_info_addresses_block_count) * 3;

        sm.set_internal_pool_block_count(ip_block_count);

        sm.set_internal_pool_bitmap_size_in_blocks(
            ip_block_count.div_ceil(sm.blocks_per_chunk() as u64) as u32,
        );
        sm.set_internal_pool_bitmap_block_count(
            sm.internal_pool_bitmap_tx_multiplier() * sm.internal_pool_bitmap_size_in_blocks(),
        );

        // Internal pool bitmap comes before the internal pool.
        let bitmap_base = initial_block;
        let ip_base = bitmap_base + sm.internal_pool_bitmap_block_count();

        sm.set_internal_pool_bitmap_base(bitmap_base);
        sm.set_internal_pool_base(ip_base);

        // fs_reserve_* left as 0.

        // free queues handled below.

        // First N blocks are occupied by the initial bitmap.
        sm.set_internal_pool_bitmap_free_head(sm.internal_pool_bitmap_size_in_blocks() as u16);
        sm.set_internal_pool_bitmap_free_tail(
            (sm.internal_pool_bitmap_block_count() - sm.internal_pool_bitmap_size_in_blocks())
                as u16,
        );
        if sm.internal_pool_bitmap_size_in_blocks() == 1
            && sm.internal_pool_bitmap_block_count() == 16
        {
            assert_eq!(sm.internal_pool_bitmap_free_head(), 1);
            assert_eq!(sm.internal_pool_bitmap_free_tail(), 15);
        }

        sm.set_internal_pool_bitmap_xid_offset(bitmap_xid_offset as _);
        sm.set_internal_pool_bitmap_offset(bitmap_offset as _);
        sm.set_internal_pool_bitmap_free_next_offset(bitmap_free_next_offset as _);

        let main_chunk_info_addresses_offset =
            bitmap_free_next_offset + sm.internal_pool_bitmap_block_count() as usize;
        let tier2_chunk_info_addresses_offset = main_chunk_info_addresses_offset
            + if chunk_info_addresses_block_count > 0 {
                chunk_info_addresses_block_count as usize
            } else {
                chunk_info_block_count as usize
            };

        sm.set_version(1);
        sm.set_struct_size(core::mem::size_of::<SpaceManagerBlockRaw>() as u32);
        assert_eq!(sm.struct_size(), 2520);

        // datazone left as all 0s.

        // Now backfill some of the fields we skipped over.

        // Main device
        {
            let device = &mut sm.devices_mut()[SpaceManagerDeviceType::Main as usize];
            device.set_block_count(block_count);
            device.set_chunk_count(chunk_count);

            if chunk_info_addresses_block_count > 0 {
                device.set_chunk_info_address_block_count(chunk_info_addresses_block_count as _);
            } else {
                device.set_chunk_info_block_count(chunk_info_block_count as _);
            }

            // TODO free count

            device.set_address_offset(main_chunk_info_addresses_offset as _);
        }

        // Tier 2 / fusion device.
        {
            let device = &mut sm.devices_mut()[SpaceManagerDeviceType::Tier2 as usize];
            device.set_address_offset(tier2_chunk_info_addresses_offset as _);
        }

        // Free queues are initially missing in Apple's implementation. Preserve that behavior.

        {
            let fq = &mut sm.free_queue_mut()[SpaceManagerFreeQueueType::InternalPool as usize];
            fq.set_tree_node_limit(1);
        }

        {
            let fq = &mut sm.free_queue_mut()[SpaceManagerFreeQueueType::Main as usize];
            fq.set_tree_node_limit(1);
        }

        let bitmap_xid = TransactionIdentifierRaw::from(1);

        let bitmap_free_next_offsets = (0..sm.internal_pool_bitmap_block_count() as usize)
            .map(|index| {
                if index < sm.internal_pool_bitmap_free_head() as usize
                    || index >= sm.internal_pool_bitmap_free_tail() as usize
                {
                    INTERNAL_POOL_BITMAP_INDEX_INVALID
                } else {
                    (index + 1) as u16
                }
            })
            .collect::<Vec<_>>();

        let chunk_info_addresses_main = vec![];
        let bitmap_blocks = vec![];

        let mut container_bitmap = ContainerBitmap::empty(1.into(), block_size, block_count);

        // Blocks occupied by the space manager are in use.
        for block in i64::from(sm.internal_pool_bitmap_base())
            ..i64::from(
                sm.internal_pool_bitmap_base()
                    + sm.internal_pool_bitmap_block_count()
                    + sm.internal_pool_block_count(),
            )
        {
            container_bitmap.set_block(block)?;
        }

        Ok(Self {
            sm,
            bitmap_xid,
            bitmap_offset: bitmap_offset as _,
            bitmap_free_next_offsets,
            chunk_info_addresses_main,
            bitmap_blocks,
            container_bitmap,
        })
    }

    /// Construct an instance from state in the space manager block.
    pub fn from_space_manager(sm: SpaceManagerBlock, reader: &impl BlockReader) -> Result<Self> {
        let bitmap_xid = sm.internal_pool_bitmap_xid()?;
        let bitmap_offset = sm.internal_pool_bitmap_offset()?;
        let bitmap_free_next_offsets = sm.internal_pool_bitmap_free_next_offsets()?;
        let chunk_info_addresses_main =
            sm.chunk_info_address_block_ids(SpaceManagerDeviceType::Main)?;

        let bitmap_base = sm.internal_pool_bitmap_base();

        let mut bitmap_blocks = Vec::with_capacity(sm.internal_pool_bitmap_block_count() as _);

        for offset in 0..sm.internal_pool_bitmap_block_count() {
            let block_number = bitmap_base + offset;
            let block = reader.get_mut_block(block_number)?;
            bitmap_blocks.push(block);
        }

        let mut chunks = vec![];

        for res in sm.iter_chunk_info_blocks(reader, SpaceManagerDeviceType::Main)? {
            let (_, cib) = res?;

            for ci in cib.trailing_data()?.iter() {
                let ci = ci?;
                chunks.push(BitmapChunk::from_reader(ci.clone_inner(), reader)?);
            }
        }

        let container_bitmap = ContainerBitmap {
            chunks: vec![],
            transaction_id: bitmap_xid,
        };

        Ok(Self {
            sm: sm.clone_inner(),
            bitmap_xid,
            bitmap_offset,
            bitmap_free_next_offsets,
            chunk_info_addresses_main,
            bitmap_blocks,
            container_bitmap,
        })
    }

    /// Iterate over the blocks providing the internal pool bitmap data.
    fn active_bitmap_blocks(&self) -> impl Iterator<Item = &MutBlock> + '_ {
        (self.bitmap_offset
            ..self.bitmap_offset + self.sm.internal_pool_bitmap_size_in_blocks() as u64)
            .map(|index| {
                let index = (index % (self.sm.internal_pool_bitmap_block_count() as u64)) as usize;

                self.bitmap_blocks
                    .get(index)
                    .expect("bitmap indices should be valid")
            })
    }

    /// Obtain the current internal pool bitmap as a bit vector.
    ///
    /// If a bit is set, the block is in use.
    pub fn bitmap(&self) -> BitVec {
        // Buffer copies could be avoided here.
        let mut input = Vec::with_capacity(
            self.sm.block_size_bytes() as usize
                * self.sm.internal_pool_bitmap_size_in_blocks() as usize,
        );

        for block in self.active_bitmap_blocks() {
            input.extend_from_slice(block.as_ref());
        }

        BitVec::from_bytes(&input)
    }

    // Advance the internal pool bitmap free next ring buffer offsets.
    fn advance_bitmap_indices(&mut self) {
        let bitmap_length = self.sm.internal_pool_bitmap_block_count() as usize;
        let entry_size = self.sm.internal_pool_bitmap_size_in_blocks() as usize;

        // Purge the tail most entry.
        let tail = self.sm.internal_pool_bitmap_free_tail() as usize;
        for index in tail..tail + entry_size {
            self.bitmap_free_next_offsets[index % bitmap_length] =
                ((index + entry_size) % bitmap_length) as u16;
        }

        self.sm
            .set_internal_pool_bitmap_free_tail(((tail + entry_size) % bitmap_length) as u16);

        // Write a new head entry.
        let head = self.sm.internal_pool_bitmap_free_head() as usize;
        for index in head..head + entry_size {
            self.bitmap_free_next_offsets[index % bitmap_length] =
                INTERNAL_POOL_BITMAP_INDEX_INVALID;
        }

        self.sm
            .set_internal_pool_bitmap_free_head(((head + entry_size) % bitmap_length) as u16);

        self.bitmap_offset = head as u64;
    }
}
