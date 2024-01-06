// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Container level reading.

use crate::block::{BlockReadError, BlockReader};
use crate::error::{ApfsError, Result};
use crate::object_map::{ObjectMap, ObjectMapBlock};
use crate::read::volume::VolumeReader;
use crate::read::FilesystemReader;
use crate::space_manager::SpaceManagerBlock;
use apfs_types::common::{
    EphemeralObjectIdentifierRaw, PhysicalObjectIdentifierRaw, TransactionIdentifierRaw,
};
use apfs_types::container::{
    CheckpointMapBlockParsed, CheckpointMappingParsed, ContainerSuperblockParsed,
    ContainerSuperblockRaw, CONTAINER_SUPERBLOCK_MAGIC,
};
use apfs_types::object::ObjectType;
use apfs_types::object_map::ObjectMapValueParsed;
use apfs_types::reaper::ReaperBlockParsed;
use apfs_types::volume::VolumeSuperblockParsed;
use apfs_types::ParsedDiskStruct;
use bytes::BytesMut;
use log::debug;
use std::io::SeekFrom;
use std::sync::{Arc, Mutex};

/// A reader for APFS containers.
///
/// This is the main type used to open an APFS filesystem/container.
///
/// This type gives you access to the container superblocks and the checkpoint
/// area.
#[derive(Clone, Debug)]
pub struct ContainerReader {
    reader: Arc<Mutex<Box<dyn FilesystemReader>>>,
    initial_position: u64,
    block_size: usize,
    initial_superblock: ContainerSuperblockParsed,
}

impl BlockReader for ContainerReader {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn read_block_into<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
        buf: &mut BytesMut,
    ) -> Result<(), BlockReadError> {
        let block_number = block_number.into();
        debug!("reading block {}", block_number);

        buf.resize(self.block_size as _, 0);

        let mut reader = self
            .reader
            .lock()
            .map_err(|_| BlockReadError::Other("reader lock poisoned"))?;
        reader.seek(SeekFrom::Start(
            self.initial_position + *block_number * self.block_size as u64,
        ))?;

        reader.read_exact(buf)?;

        Ok(())
    }
}

impl ContainerReader {
    /// Construct a new instance from a filesystem reader.
    pub fn new(mut reader: Box<dyn FilesystemReader>) -> Result<Self> {
        let initial_position = reader.stream_position().map_err(BlockReadError::from)?;

        // Block size may not be 4096 but 4096 is guaranteed large enough to
        // hold the initial superblock. And 4096 is the minimum block size.
        let mut buf = BytesMut::zeroed(4096);
        reader.read_exact(&mut buf).map_err(BlockReadError::from)?;

        let initial_superblock = ContainerSuperblockParsed::from_bytes(buf.freeze())?;

        let block_size = initial_superblock.block_size_bytes() as usize;

        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            initial_position,
            block_size,
            initial_superblock,
        })
    }

    /// Obtain the superblock at block 0.
    pub fn block_zero_superblock(&self) -> &ContainerSuperblockParsed {
        &self.initial_superblock
    }

    /// Iterate superblocks in this container.
    pub fn iter_superblocks(&self) -> impl Iterator<Item = Result<ContainerSuperblockParsed>> + '_ {
        let start_block = u64::from(
            self.initial_superblock
                .checkpoint_descriptor_area_block_number(),
        );
        let block_count = self
            .initial_superblock
            .checkpoint_descriptor_area_block_count() as u64;

        (start_block..start_block + block_count)
            .map(|number| {
                let block = self.get_block(number)?;

                let obj = block.object_header()?;

                if obj.typ().object_type() == ObjectType::ContainerSuperblock {
                    let sb = ContainerSuperblockParsed::from_bytes(block.bytes())?;

                    if sb.magic() == CONTAINER_SUPERBLOCK_MAGIC {
                        block.validate_checksum()?;
                        Ok(Some(sb))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            })
            .filter_map(|res| match res {
                Ok(Some(x)) => Some(Ok(x)),
                Ok(None) => None,
                Err(err) => Some(Err(err)),
            })
    }

    /// Obtain all known superblocks sorted from newest to oldest.
    pub fn superblocks_sorted(&self) -> Result<Vec<ContainerSuperblockParsed>> {
        let mut sbs = self.iter_superblocks().collect::<Result<Vec<_>>>()?;

        sbs.sort_by_key(|sb| -(u64::from(sb.object().transaction_identifier()) as i64));

        Ok(sbs)
    }

    /// Find the latest superblock.
    pub fn superblock_latest(&self) -> Result<ContainerSuperblockParsed> {
        let sbs = self.superblocks_sorted()?;

        sbs.into_iter()
            .next()
            .ok_or_else(|| ApfsError::NoSuperblock)
    }

    /// Find the superblock for a given transaction identifier.
    pub fn superblock_transaction(
        &self,
        txn: TransactionIdentifierRaw,
    ) -> Result<Option<ContainerSuperblockParsed>> {
        for sb in self.iter_superblocks() {
            match sb {
                Ok(sb) => {
                    if sb.object().transaction_identifier() == txn {
                        return Ok(Some(sb));
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(None)
    }

    /// Obtain a reader using the newest superblock.
    pub fn superblock_reader_latest(&self) -> Result<SuperblockReader> {
        let sb = self.superblock_latest()?;

        SuperblockReader::new(self.clone(), sb)
    }

    /// Obtain a reader for the superblock bound to a specific transaction.
    pub fn superblock_reader_transaction(
        &self,
        txn: TransactionIdentifierRaw,
    ) -> Result<Option<SuperblockReader>> {
        if let Some(sb) = self.superblock_transaction(txn)? {
            Ok(Some(SuperblockReader::new(self.clone(), sb)?))
        } else {
            Ok(None)
        }
    }

    /// Iterate over checkpoint map blocks for a given superblock.
    pub fn checkpoint_map_blocks(
        &self,
        sb: &ContainerSuperblockRaw,
    ) -> Result<impl Iterator<Item = Result<CheckpointMapBlockParsed>> + '_> {
        let base = sb.checkpoint_descriptor_area_block_number();

        if i64::from(base) < 0 {
            return Err(ApfsError::Unimplemented(
                "checkpoint descriptor area stored as a B-tree",
            ));
        }

        let count = sb.checkpoint_descriptor_area_block_count();
        let start = sb.checkpoint_descriptor_area_start_index();
        let length = sb.checkpoint_descriptor_area_length();

        Ok((start..start + length)
            .map(move |index| {
                let block_number = if index > count {
                    return Err(ApfsError::Unimplemented("wrapping descriptor area indices"));
                } else {
                    base + index
                };

                let block = self.get_block(block_number)?;

                let obj = block.object_header()?;

                if obj.typ().object_type() == ObjectType::CheckpointMap {
                    block.validate_checksum()?;
                    let map = CheckpointMapBlockParsed::from_bytes(block.bytes())?;

                    Ok(Some(map))
                } else {
                    Ok(None)
                }
            })
            .filter_map(|res| match res {
                Ok(Some(x)) => Some(Ok(x)),
                Ok(None) => None,
                Err(err) => Some(Err(err)),
            }))
    }
}

/// A reader bound to a specific superblock within a container.
///
/// This gives you access to all the global data structures within a container,
/// as defined by a superblock. Instances are derived from [ContainerRaider].
pub struct SuperblockReader {
    inner: ContainerReader,
    superblock: ContainerSuperblockParsed,
    checkpoint_mappings: Vec<CheckpointMappingParsed>,
}

impl BlockReader for SuperblockReader {
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn read_block_into<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
        buf: &mut BytesMut,
    ) -> Result<(), BlockReadError> {
        self.inner.read_block_into(block_number, buf)
    }
}

impl SuperblockReader {
    /// Construct an instance from a [ContainerReader] and superblock instance.
    pub fn new(reader: ContainerReader, superblock: ContainerSuperblockParsed) -> Result<Self> {
        // Load checkpoint mappings into memory.
        let mut checkpoint_mappings = vec![];

        for mappings in reader.checkpoint_map_blocks(&superblock)? {
            let mappings = mappings?;
            let trailing_data = mappings.trailing_data()?;

            for mapping in trailing_data.iter() {
                let mapping = mapping?;

                checkpoint_mappings.push(mapping);
            }
        }

        Ok(Self {
            inner: reader,
            superblock,
            checkpoint_mappings,
        })
    }

    /// Resolve metadata about an ephemeral object identifier.
    pub fn find_ephemeral_object_mapping(
        &self,
        oid: EphemeralObjectIdentifierRaw,
    ) -> Option<&CheckpointMappingParsed> {
        self.checkpoint_mappings
            .iter()
            .find(|mapping| mapping.container_identifier() == oid)
    }

    /// Obtain the object map for this instance.
    pub fn object_map(&self) -> Result<ObjectMapBlock> {
        let block = self
            .inner
            .get_block_validated(self.superblock.object_map_block_number())?;

        ObjectMapBlock::new(self, block)
    }

    /// Iterate over object map values belonging to volumes.
    ///
    /// This resolves the volume object identifiers in the superblock to their
    /// object map entries. This should yield data structures having the
    /// address of the volume superblock.
    pub fn iter_volume_object_map_values(
        &self,
    ) -> Result<impl Iterator<Item = ObjectMapValueParsed> + '_> {
        let om = self.object_map()?;

        Ok(self
            .superblock
            .volume_oids()
            .iter()
            .copied()
            .filter_map(move |volume_oid| {
                if let Ok(Some((_, v))) = om.find_latest_oid(
                    self,
                    volume_oid,
                    self.superblock.object().transaction_identifier(),
                ) {
                    Some(v)
                } else {
                    None
                }
            }))
    }

    /// Iterate over volume superblocks referenced by this superblock.
    pub fn iter_volume_superblocks(
        &self,
    ) -> Result<impl Iterator<Item = Result<VolumeSuperblockParsed>> + '_> {
        Ok(self.iter_volume_object_map_values()?.map(|v| {
            debug!("reading block {} as volume superblock", v.address());
            let block = self.get_block_validated(v.address())?;
            Ok(VolumeSuperblockParsed::from_bytes(block.bytes())?)
        }))
    }

    /// Obtain [VolumeReader] instances for every volume referenced by this superblock.
    pub fn iter_volume_readers(
        &self,
    ) -> Result<impl Iterator<Item = Result<VolumeReader<Self>>> + '_> {
        Ok(self
            .iter_volume_superblocks()?
            .map(|vsb| vsb.and_then(|vsb| VolumeReader::new(self, vsb))))
    }

    /// Obtain the reaper block.
    pub fn reaper(&self) -> Result<ReaperBlockParsed> {
        let oid = self
            .find_ephemeral_object_mapping(self.superblock.reaper_oid())
            .ok_or(ApfsError::ReaperNotFound)?;
        let block = self.inner.get_block_validated(oid.address())?;

        Ok(ReaperBlockParsed::from_bytes(block.bytes())?)
    }

    /// Obtain the space manager.
    pub fn space_manager(&self) -> Result<SpaceManagerBlock> {
        let oid = self
            .find_ephemeral_object_mapping(self.superblock.space_manager_oid())
            .ok_or(ApfsError::SpaceManagerNotFound)?;

        let block = self.inner.get_block_validated(oid.address())?;

        SpaceManagerBlock::new(block)
    }
}
