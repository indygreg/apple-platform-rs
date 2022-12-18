// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use {
    anyhow::Result,
    byteorder::{ReadBytesExt, WriteBytesExt, BE},
    std::io::{Read, Seek, SeekFrom, Write},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdifChecksum {
    pub r#type: u32,
    pub size: u32,
    pub data: [u8; 128],
}

impl Default for UdifChecksum {
    fn default() -> Self {
        Self {
            r#type: 2,
            size: 32,
            data: [0; 128],
        }
    }
}

impl UdifChecksum {
    pub fn new(crc32: u32) -> Self {
        let mut data = [0; 128];
        data[..4].copy_from_slice(&crc32.to_be_bytes());
        Self {
            data,
            ..Default::default()
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(crc32fast::hash(bytes))
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let r#type = r.read_u32::<BE>()?;
        let size = r.read_u32::<BE>()?;
        let mut data = [0; 128];
        r.read_exact(&mut data)?;
        Ok(Self { r#type, size, data })
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_u32::<BE>(self.r#type)?;
        w.write_u32::<BE>(self.size)?;
        w.write_all(&self.data)?;
        Ok(())
    }
}

impl From<UdifChecksum> for u32 {
    fn from(checksum: UdifChecksum) -> Self {
        let mut data = [0; 4];
        data.copy_from_slice(&checksum.data[..4]);
        u32::from_be_bytes(data)
    }
}

const KOLY_SIZE: i64 = 512;

/// DMG trailer describing file content.
///
/// This is the main structure defining a DMG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KolyTrailer {
    // "koly" signature: [u8; 4],
    pub version: u32,
    //header_size: u32,
    pub flags: u32,
    pub running_data_fork_offset: u64,
    pub data_fork_offset: u64,
    pub data_fork_length: u64,
    pub resource_fork_offset: u64,
    pub resource_fork_length: u64,
    pub segment_number: u32,
    pub segment_count: u32,
    pub segment_id: [u8; 16],
    pub data_fork_digest: UdifChecksum,
    pub plist_offset: u64,
    pub plist_length: u64,
    pub reserved1: [u8; 64],
    pub code_signature_offset: u64,
    pub code_signature_size: u64,
    pub reserved2: [u8; 40],
    pub main_digest: UdifChecksum,
    pub image_variant: u32,
    pub sector_count: u64,
    pub reserved3: [u8; 12],
}

impl Default for KolyTrailer {
    fn default() -> Self {
        Self {
            version: 4,
            flags: 1,
            running_data_fork_offset: 0,
            data_fork_offset: 0,
            data_fork_length: 0,
            resource_fork_offset: 0,
            resource_fork_length: 0,
            segment_number: 1,
            segment_count: 1,
            segment_id: [0; 16],
            data_fork_digest: UdifChecksum::default(),
            plist_offset: 0,
            plist_length: 0,
            reserved1: [0; 64],
            code_signature_offset: 0,
            code_signature_size: 0,
            reserved2: [0; 40],
            main_digest: UdifChecksum::default(),
            image_variant: 1,
            sector_count: 0,
            reserved3: [0; 12],
        }
    }
}

impl KolyTrailer {
    pub fn new(
        data_fork_length: u64,
        sectors: u64,
        plist_offset: u64,
        plist_length: u64,
        data_digest: u32,
        main_digest: u32,
    ) -> Self {
        let mut segment_id = [0; 16];
        getrandom::getrandom(&mut segment_id).unwrap();
        Self {
            data_fork_length,
            sector_count: sectors,
            plist_offset,
            plist_length,
            data_fork_digest: UdifChecksum::new(data_digest),
            main_digest: UdifChecksum::new(main_digest),
            segment_id,
            ..Default::default()
        }
    }

    /// Construct an instance by reading from a seekable reader.
    ///
    /// The trailer is the final 512 bytes of the seekable stream.
    pub fn read_from<R: Read + Seek>(r: &mut R) -> Result<Self> {
        r.seek(SeekFrom::End(-KOLY_SIZE))?;

        let mut signature = [0; 4];
        r.read_exact(&mut signature)?;
        anyhow::ensure!(&signature == b"koly");
        let version = r.read_u32::<BE>()?;
        let header_size = r.read_u32::<BE>()?;
        anyhow::ensure!(header_size == 512);
        let flags = r.read_u32::<BE>()?;
        let running_data_fork_offset = r.read_u64::<BE>()?;
        let data_fork_offset = r.read_u64::<BE>()?;
        let data_fork_length = r.read_u64::<BE>()?;
        let resource_fork_offset = r.read_u64::<BE>()?;
        let resource_fork_length = r.read_u64::<BE>()?;
        let segment_number = r.read_u32::<BE>()?;
        let segment_count = r.read_u32::<BE>()?;
        let mut segment_id = [0; 16];
        r.read_exact(&mut segment_id)?;
        let data_fork_digest = UdifChecksum::read_from(r)?;
        let plist_offset = r.read_u64::<BE>()?;
        let plist_length = r.read_u64::<BE>()?;
        let mut reserved1 = [0; 64];
        r.read_exact(&mut reserved1)?;
        let code_signature_offset = r.read_u64::<BE>()?;
        let code_signature_size = r.read_u64::<BE>()?;
        let mut reserved2 = [0; 40];
        r.read_exact(&mut reserved2)?;
        let main_digest = UdifChecksum::read_from(r)?;
        let image_variant = r.read_u32::<BE>()?;
        let sector_count = r.read_u64::<BE>()?;
        let mut reserved3 = [0; 12];
        r.read_exact(&mut reserved3)?;
        Ok(Self {
            version,
            flags,
            running_data_fork_offset,
            data_fork_offset,
            data_fork_length,
            resource_fork_offset,
            resource_fork_length,
            segment_number,
            segment_count,
            segment_id,
            data_fork_digest,
            plist_offset,
            plist_length,
            reserved1,
            code_signature_offset,
            code_signature_size,
            reserved2,
            main_digest,
            image_variant,
            sector_count,
            reserved3,
        })
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(b"koly")?;
        w.write_u32::<BE>(self.version)?;
        w.write_u32::<BE>(KOLY_SIZE as u32)?;
        w.write_u32::<BE>(self.flags)?;
        w.write_u64::<BE>(self.running_data_fork_offset)?;
        w.write_u64::<BE>(self.data_fork_offset)?;
        w.write_u64::<BE>(self.data_fork_length)?;
        w.write_u64::<BE>(self.resource_fork_offset)?;
        w.write_u64::<BE>(self.resource_fork_length)?;
        w.write_u32::<BE>(self.segment_number)?;
        w.write_u32::<BE>(self.segment_count)?;
        w.write_all(&self.segment_id)?;
        self.data_fork_digest.write_to(w)?;
        w.write_u64::<BE>(self.plist_offset)?;
        w.write_u64::<BE>(self.plist_length)?;
        w.write_all(&self.reserved1)?;
        w.write_u64::<BE>(self.code_signature_offset)?;
        w.write_u64::<BE>(self.code_signature_size)?;
        w.write_all(&self.reserved2)?;
        self.main_digest.write_to(w)?;
        w.write_u32::<BE>(self.image_variant)?;
        w.write_u64::<BE>(self.sector_count)?;
        w.write_all(&self.reserved3)?;
        Ok(())
    }
}
