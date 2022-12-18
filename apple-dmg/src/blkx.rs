// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use {
    crate::koly::UdifChecksum,
    anyhow::Result,
    byteorder::{ReadBytesExt, WriteBytesExt, BE},
    std::io::{Read, Write},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlkxTable {
    /// currently 1
    pub version: u32,
    /// starting sector
    pub sector_number: u64,
    /// number of sectors
    pub sector_count: u64,
    /// seems to always be 0
    pub data_offset: u64,
    /// seems to be a magic constant for zlib describing the buffer size
    /// required for decompressing a chunk.
    pub buffers_needed: u32,
    /// not sure what this is, setting it to the partition index
    pub block_descriptors: u32,
    pub reserved: [u8; 24],
    pub checksum: UdifChecksum,
    /// chunk table
    pub chunks: Vec<BlkxChunk>,
}

impl Default for BlkxTable {
    fn default() -> Self {
        Self {
            version: 1,
            sector_number: 0,
            sector_count: 0,
            data_offset: 0,
            //  number was taken from hdiutil
            buffers_needed: 2056,
            block_descriptors: 0,
            reserved: [0; 24],
            checksum: UdifChecksum::default(),
            chunks: vec![],
        }
    }
}

impl BlkxTable {
    pub fn new(index: u32, sector: u64, checksum: u32) -> Self {
        Self {
            block_descriptors: index,
            sector_number: sector,
            checksum: UdifChecksum::new(checksum),
            ..Default::default()
        }
    }

    pub fn add_chunk(&mut self, mut chunk: BlkxChunk) {
        chunk.sector_number = self.sector_count;
        self.sector_count += chunk.sector_count;
        self.chunks.push(chunk);
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut signature = [0; 4];
        r.read_exact(&mut signature)?;
        anyhow::ensure!(&signature == b"mish");
        let version = r.read_u32::<BE>()?;
        let sector_number = r.read_u64::<BE>()?;
        let sector_count = r.read_u64::<BE>()?;
        let data_offset = r.read_u64::<BE>()?;
        let buffers_needed = r.read_u32::<BE>()?;
        let block_descriptors = r.read_u32::<BE>()?;
        let mut reserved = [0; 24];
        r.read_exact(&mut reserved)?;
        let checksum = UdifChecksum::read_from(r)?;
        let num_chunks = r.read_u32::<BE>()?;
        let mut chunks = Vec::with_capacity(num_chunks as _);
        for _ in 0..num_chunks {
            chunks.push(BlkxChunk::read_from(r)?);
        }
        Ok(Self {
            version,
            sector_number,
            sector_count,
            data_offset,
            buffers_needed,
            block_descriptors,
            reserved,
            checksum,
            chunks,
        })
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(b"mish")?;
        w.write_u32::<BE>(self.version)?;
        w.write_u64::<BE>(self.sector_number)?;
        w.write_u64::<BE>(self.sector_count)?;
        w.write_u64::<BE>(self.data_offset)?;
        w.write_u32::<BE>(self.buffers_needed)?;
        w.write_u32::<BE>(self.block_descriptors)?;
        w.write_all(&self.reserved)?;
        self.checksum.write_to(w)?;
        w.write_u32::<BE>(self.chunks.len() as u32)?;
        for chunk in &self.chunks {
            chunk.write_to(w)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlkxChunk {
    /// compression type used for this chunk
    pub r#type: u32,
    pub comment: u32,
    pub sector_number: u64,
    pub sector_count: u64,
    pub compressed_offset: u64,
    pub compressed_length: u64,
}

impl Default for BlkxChunk {
    fn default() -> Self {
        Self {
            r#type: ChunkType::Raw as _,
            comment: 0,
            sector_number: 0,
            sector_count: 0,
            compressed_offset: 0,
            compressed_length: 0,
        }
    }
}

impl BlkxChunk {
    pub fn new(
        ty: ChunkType,
        sector_number: u64,
        sector_count: u64,
        compressed_offset: u64,
        compressed_length: u64,
    ) -> Self {
        Self {
            r#type: ty as _,
            sector_number,
            sector_count,
            compressed_offset,
            compressed_length,
            ..Default::default()
        }
    }

    pub fn term(sector_number: u64, compressed_offset: u64) -> Self {
        Self::new(ChunkType::Term, sector_number, 0, compressed_offset, 0)
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let r#type = r.read_u32::<BE>()?;
        let comment = r.read_u32::<BE>()?;
        let sector_number = r.read_u64::<BE>()?;
        let sector_count = r.read_u64::<BE>()?;
        let compressed_offset = r.read_u64::<BE>()?;
        let compressed_length = r.read_u64::<BE>()?;
        Ok(Self {
            r#type,
            comment,
            sector_number,
            sector_count,
            compressed_offset,
            compressed_length,
        })
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_u32::<BE>(self.r#type)?;
        w.write_u32::<BE>(self.comment)?;
        w.write_u64::<BE>(self.sector_number)?;
        w.write_u64::<BE>(self.sector_count)?;
        w.write_u64::<BE>(self.compressed_offset)?;
        w.write_u64::<BE>(self.compressed_length)?;
        Ok(())
    }

    pub fn ty(self) -> Option<ChunkType> {
        ChunkType::from_u32(self.r#type)
    }
}

/// Possible compression types of the BlkxChunk.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkType {
    Zero = 0x0000_0000,
    Raw = 0x0000_0001,
    Ignore = 0x0000_0002,
    Comment = 0x7fff_fffe,
    Adc = 0x8000_0004,
    Zlib = 0x8000_0005,
    Bzlib = 0x8000_0006,
    Lzfse = 0x8000_0007,
    Term = 0xffff_ffff,
}

impl ChunkType {
    pub fn from_u32(ty: u32) -> Option<Self> {
        Some(match ty {
            x if x == ChunkType::Zero as u32 => ChunkType::Zero,
            x if x == ChunkType::Raw as u32 => ChunkType::Raw,
            x if x == ChunkType::Ignore as u32 => ChunkType::Ignore,
            x if x == ChunkType::Comment as u32 => ChunkType::Comment,
            x if x == ChunkType::Adc as u32 => ChunkType::Adc,
            x if x == ChunkType::Zlib as u32 => ChunkType::Zlib,
            x if x == ChunkType::Bzlib as u32 => ChunkType::Bzlib,
            x if x == ChunkType::Lzfse as u32 => ChunkType::Lzfse,
            x if x == ChunkType::Term as u32 => ChunkType::Term,
            _ => return None,
        })
    }
}
