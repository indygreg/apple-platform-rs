// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Block-level primitives.

use crate::error::{ApfsError, Result};
use apfs_types::common::PhysicalObjectIdentifierRaw;
use apfs_types::object::ObjectHeaderParsed;
use apfs_types::ParsedDiskStruct;
use bytes::{Bytes, BytesMut};
use log::trace;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use thiserror::Error;

/// Error for a block reading operation.
#[derive(Debug, Error)]
pub enum BlockReadError {
    #[error("block number {0} is out of bounds")]
    BlockBounds(PhysicalObjectIdentifierRaw),
    #[error("I/O error reading block data: {0}")]
    Io(#[from] std::io::Error),
    #[error("other block reading error: {0}")]
    Other(&'static str),
}

/// Interface for reading blocks.
pub trait BlockReader {
    /// Obtain the size of blocks in bytes.
    fn block_size(&self) -> usize;

    /// Read a block's data into the specified bytes buffer.
    ///
    /// Implementations must guarantee the following when returning Ok:
    ///
    /// * The [BytesMut] has length set to the container's block size.
    /// * The full block size is read into the [BytesMut]. No partial reads.
    ///
    /// These conditions can be achieved by calling `buf.resize(block_size)`
    /// and `read_exact(buf)` on a [std::io::Read] instance.
    fn read_block_into<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
        buf: &mut BytesMut,
    ) -> Result<(), BlockReadError>;

    /// Read block data into a new buffer allocated by this function.
    fn read_block_data<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
    ) -> Result<Bytes, BlockReadError> {
        let mut buf = BytesMut::zeroed(self.block_size());
        self.read_block_into(block_number, &mut buf)?;

        Ok(buf.freeze())
    }

    /// Resolve a [Block] instance for a specified block number.
    ///
    /// The default implementation will read the block data and construct
    /// a new instance.
    ///
    /// Custom implementations could implement their own caching layer
    /// that avoids I/O.
    fn get_block<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
    ) -> Result<Block, BlockReadError> {
        let number = block_number.into();
        let buf = self.read_block_data(number)?;

        Ok(Block::new(number, buf))
    }

    /// Get a block and validate its checksum.
    ///
    /// You should call this instead of [Self::get_block] when you know the
    /// block you are reading has a physical object header / checksum.
    fn get_block_validated<N: Into<PhysicalObjectIdentifierRaw>>(
        &self,
        block_number: N,
    ) -> Result<Block, ApfsError> {
        let block = self.get_block(block_number)?;
        block.validate_checksum()?;

        Ok(block)
    }
}

fn fletcher64(input: &[u8]) -> u64 {
    let mut sum1 = 0u64;
    let mut sum2 = 0u64;

    for chunk in input.chunks(4) {
        sum1 += u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        sum2 += sum1;
    }

    let c1 = sum1 + sum2;
    let c1 = 0xffffffff - (c1 % 0xffffffff);
    let c2 = sum1 + c1;
    let c2 = 0xffffffff - (c2 % 0xffffffff);

    (c2 << 32) | c1
}

/// A container block and its underlying data.
pub struct Block {
    number: PhysicalObjectIdentifierRaw,
    buf: Bytes,
}

impl Deref for Block {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl Block {
    /// Construct an instance from its block number and read data.
    pub fn new(number: PhysicalObjectIdentifierRaw, buf: Bytes) -> Self {
        Self { number, buf }
    }

    /// The block number.
    ///
    /// 0 is the first block.
    pub fn number(&self) -> PhysicalObjectIdentifierRaw {
        self.number
    }

    /// Obtain the raw bytes backing this block.
    pub fn bytes(&self) -> Bytes {
        self.buf.clone()
    }

    /// Compute the fletcher checksum for this block containing a physical object.
    ///
    /// This will checksum the full block minus the first 8 bytes, which are used to
    /// store the checksum.
    pub fn checksum_object(&self) -> u64 {
        fletcher64(&self.buf.as_ref()[8..])
    }

    /// Ensure the checksum is valid, returning an error if not.
    pub fn validate_checksum(&self) -> Result<(), ApfsError> {
        let header = self.object_header()?;

        if header.checksum() == self.checksum_object() {
            Ok(())
        } else {
            Err(ApfsError::InvalidChecksum)
        }
    }

    /// Resolve a parsed common object header from this block.
    ///
    /// Blocks are guaranteed to be large enough to hold the common object header.
    /// However, not all blocks contain the object header. Calling this on
    /// headerless blocks will return garbage values in the header.
    ///
    /// It is up to callers to validate the block's validity.
    pub fn object_header(&self) -> Result<ObjectHeaderParsed> {
        Ok(ObjectHeaderParsed::from_bytes(self.buf.clone())?)
    }
}

pub struct BlockRangeReader<'a, R: BlockReader> {
    reader: &'a R,
    start_block: u64,
    block_count: u64,
    current_block: u64,
    partial_block: Option<Bytes>,
}

impl<'a, R: BlockReader> BlockRangeReader<'a, R> {
    /// Construct a new instance configured to read N blocks starting at given block number.
    pub fn new<N: Into<PhysicalObjectIdentifierRaw>>(
        reader: &'a R,
        start_block: N,
        block_count: u64,
    ) -> Self {
        let start_block = start_block.into();

        Self {
            reader,
            start_block: start_block.0,
            block_count,
            current_block: start_block.0,
            partial_block: None,
        }
    }

    const fn finish_block(&self) -> u64 {
        self.start_block + self.block_count
    }
}

impl<'a, R: BlockReader> Read for BlockRangeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut buf_offset = 0;

        while buf_offset < buf.len() {
            let mut dest = &mut buf[buf_offset..];

            assert!(
                !dest.is_empty(),
                "non-empty buffer ensured by loop condition"
            );

            // Use partial block if available. Otherwise read the next block if
            // able.
            let input = if let Some(remaining) = self.partial_block.take() {
                remaining
            } else if self.current_block >= self.finish_block() {
                return Ok(buf_offset);
            } else {
                let block = self
                    .reader
                    .get_block(self.current_block)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                self.current_block += 1;
                block.buf
            };

            let written = dest.write(input.as_ref())?;
            trace!("BlockRangeReader read({}) -> {}", input.len(), written);
            buf_offset += written;

            let input = input.slice(written..);

            // We still have data left over in the input block. This implies
            // that the destination buffer is full, otherwise all data would have
            // been written to it. Stash the input buffer and return.
            if !input.is_empty() {
                self.partial_block = Some(input);
                return Ok(buf_offset);
            }

            // The input is empty. At this point we repeat the loop.
            // If the destination buffer is full, we exit loop. Otherwise
            // loop attempts to read more input.
        }

        Ok(buf_offset)
    }
}

impl<'a, R: BlockReader> Seek for BlockRangeReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let block_size = self.reader.block_size() as u64;

        match pos {
            SeekFrom::Start(pos) => {
                let total_blocks = pos / block_size;
                let remainder = pos % block_size;

                self.current_block = self.start_block + total_blocks;

                if remainder != 0 {
                    let block = self
                        .reader
                        .get_block(self.current_block)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    self.current_block += 1;
                    let partial = block.buf.slice(remainder as usize..);
                    self.partial_block = Some(partial);
                } else {
                    self.partial_block = None;
                }

                Ok(pos)
            }
            SeekFrom::End(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "seeking from end is not implemented",
            )),
            SeekFrom::Current(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "seeking from current location is not implemented",
            )),
        }
    }
}
