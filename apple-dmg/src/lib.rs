// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use {
    anyhow::Result,
    crc32fast::Hasher,
    fatfs::{Dir, FileSystem, FormatVolumeOptions, FsOptions, ReadWriteSeek},
    flate2::{bufread::ZlibEncoder, read::ZlibDecoder, Compression},
    fscommon::BufStream,
    gpt::mbr::{PartRecord, ProtectiveMBR},
    std::{
        fs::File,
        io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
        path::Path,
    },
};

mod blkx;
mod koly;
mod xml;

pub use crate::{blkx::*, koly::*, xml::*};

pub struct DmgReader<R: Read + Seek> {
    koly: KolyTrailer,
    xml: Plist,
    r: R,
}

impl DmgReader<BufReader<File>> {
    pub fn open(path: &Path) -> Result<Self> {
        let r = BufReader::new(File::open(path)?);
        Self::new(r)
    }
}

impl<R: Read + Seek> DmgReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let koly = KolyTrailer::read_from(&mut r)?;
        r.seek(SeekFrom::Start(koly.plist_offset))?;
        let mut xml = Vec::with_capacity(koly.plist_length as usize);
        (&mut r).take(koly.plist_length).read_to_end(&mut xml)?;
        let xml: Plist = plist::from_reader_xml(&xml[..])?;
        Ok(Self { koly, xml, r })
    }

    pub fn koly(&self) -> &KolyTrailer {
        &self.koly
    }

    pub fn plist(&self) -> &Plist {
        &self.xml
    }

    pub fn sector(&mut self, chunk: &BlkxChunk) -> Result<impl Read + '_> {
        self.r.seek(SeekFrom::Start(chunk.compressed_offset))?;
        let compressed_chunk = (&mut self.r).take(chunk.compressed_length);
        match chunk.ty().expect("unknown chunk type") {
            ChunkType::Ignore | ChunkType::Zero | ChunkType::Comment => {
                Ok(Box::new(std::io::repeat(0).take(chunk.compressed_length)) as Box<dyn Read>)
            }
            ChunkType::Raw => Ok(Box::new(compressed_chunk)),
            ChunkType::Zlib => Ok(Box::new(ZlibDecoder::new(compressed_chunk))),
            ChunkType::Adc | ChunkType::Bzlib | ChunkType::Lzfse => unimplemented!(),
            ChunkType::Term => Ok(Box::new(std::io::empty())),
        }
    }

    pub fn data_checksum(&mut self) -> Result<u32> {
        self.r.seek(SeekFrom::Start(self.koly.data_fork_offset))?;
        let mut data_fork = Vec::with_capacity(self.koly.data_fork_length as usize);
        (&mut self.r)
            .take(self.koly.data_fork_length)
            .read_to_end(&mut data_fork)?;
        Ok(crc32fast::hash(&data_fork))
    }

    pub fn partition_table(&self, i: usize) -> Result<BlkxTable> {
        self.plist().partitions()[i].table()
    }

    pub fn partition_name(&self, i: usize) -> &str {
        &self.plist().partitions()[i].name
    }

    pub fn partition_data(&mut self, i: usize) -> Result<Vec<u8>> {
        let table = self.plist().partitions()[i].table()?;
        let mut partition = vec![];
        for chunk in &table.chunks {
            std::io::copy(&mut self.sector(chunk)?, &mut partition)?;
        }
        Ok(partition)
    }
}

pub struct DmgWriter<W: Write + Seek> {
    xml: Plist,
    w: W,
    data_hasher: Hasher,
    main_hasher: Hasher,
    sector_number: u64,
    compressed_offset: u64,
}

impl DmgWriter<BufWriter<File>> {
    pub fn create(path: &Path) -> Result<Self> {
        let w = BufWriter::new(File::create(path)?);
        Ok(Self::new(w))
    }
}

impl<W: Write + Seek> DmgWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            xml: Default::default(),
            w,
            data_hasher: Hasher::new(),
            main_hasher: Hasher::new(),
            sector_number: 0,
            compressed_offset: 0,
        }
    }

    pub fn create_fat32(mut self, fat32: &[u8]) -> Result<()> {
        anyhow::ensure!(fat32.len() % 512 == 0);
        let sector_count = fat32.len() as u64 / 512;
        let mut mbr = ProtectiveMBR::new();
        let mut partition = PartRecord::new_protective(Some(sector_count.try_into()?));
        partition.os_type = 11;
        mbr.set_partition(0, partition);
        let mbr = mbr.as_bytes()?;
        self.add_partition("Master Boot Record (MBR : 0)", &mbr)?;
        self.add_partition("FAT32 (FAT32 : 1)", fat32)?;
        self.finish()?;
        Ok(())
    }

    pub fn add_partition(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(bytes.len() % 512 == 0);
        let id = self.xml.partitions().len() as u32;
        let name = name.to_string();
        let mut table = BlkxTable::new(id, self.sector_number, crc32fast::hash(bytes));
        for chunk in bytes.chunks(2048 * 512) {
            let mut encoder = ZlibEncoder::new(chunk, Compression::best());
            let mut compressed = vec![];
            encoder.read_to_end(&mut compressed)?;
            let compressed_length = compressed.len() as u64;
            let sector_count = chunk.len() as u64 / 512;
            self.w.write_all(&compressed)?;
            self.data_hasher.update(&compressed);
            table.add_chunk(BlkxChunk::new(
                ChunkType::Zlib,
                self.sector_number,
                sector_count,
                self.compressed_offset,
                compressed_length,
            ));
            self.sector_number += sector_count;
            self.compressed_offset += compressed_length;
        }
        table.add_chunk(BlkxChunk::term(self.sector_number, self.compressed_offset));
        self.main_hasher.update(&table.checksum.data[..4]);
        self.xml
            .add_partition(Partition::new(id as i32 - 1, name, table));
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        let mut xml = vec![];
        plist::to_writer_xml(&mut xml, &self.xml)?;
        let pos = self.w.stream_position()?;
        let data_digest = self.data_hasher.finalize();
        let main_digest = self.main_hasher.finalize();
        let koly = KolyTrailer::new(
            pos,
            self.sector_number,
            pos,
            xml.len() as _,
            data_digest,
            main_digest,
        );
        self.w.write_all(&xml)?;
        koly.write_to(&mut self.w)?;
        Ok(())
    }
}

// https://wiki.samba.org/index.php/UNIX_Extensions#Storing_symlinks_on_Windows_servers
fn symlink(target: &str) -> Result<Vec<u8>> {
    let xsym = format!(
        "XSym\n{:04}\n{:x}\n{}\n",
        target.as_bytes().len(),
        md5::compute(target.as_bytes()),
        target,
    );
    let mut xsym = xsym.into_bytes();
    anyhow::ensure!(xsym.len() <= 1067);
    xsym.resize(1067, b' ');
    Ok(xsym)
}

fn add_dir<T: ReadWriteSeek>(src: &Path, dest: &Dir<'_, T>) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_str().unwrap();
        let source = src.join(file_name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let d = dest.create_dir(file_name)?;
            add_dir(&source, &d)?;
        } else if file_type.is_file() {
            let mut f = dest.create_file(file_name)?;
            std::io::copy(&mut File::open(source)?, &mut f)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&source)?;
            let xsym = symlink(target.to_str().unwrap())?;
            let mut f = dest.create_file(file_name)?;
            std::io::copy(&mut &xsym[..], &mut f)?;
        }
    }
    Ok(())
}

pub fn create_dmg(dir: &Path, dmg: &Path, volume_label: &str, total_sectors: u32) -> Result<()> {
    let mut fat32 = vec![0; total_sectors as usize * 512];
    {
        let mut volume_label_bytes = [0; 11];
        let end = std::cmp::min(volume_label_bytes.len(), volume_label.len());
        volume_label_bytes[..end].copy_from_slice(&volume_label.as_bytes()[..end]);
        let volume_options = FormatVolumeOptions::new()
            .volume_label(volume_label_bytes)
            .bytes_per_sector(512)
            .total_sectors(total_sectors);
        let mut disk = BufStream::new(Cursor::new(&mut fat32));
        fatfs::format_volume(&mut disk, volume_options)?;
        let fs = FileSystem::new(disk, FsOptions::new())?;
        let file_name = dir.file_name().unwrap().to_str().unwrap();
        let dest = fs.root_dir().create_dir(file_name)?;
        add_dir(dir, &dest)?;
    }
    DmgWriter::create(dmg)?.create_fat32(&fat32)
}

#[cfg(test)]
mod tests {
    use {super::*, gpt::disk::LogicalBlockSize};

    static DMG: &[u8] = include_bytes!("../assets/example.dmg");

    fn print_dmg<R: Read + Seek>(dmg: &DmgReader<R>) -> Result<()> {
        println!("{:?}", dmg.koly());
        println!("{:?}", dmg.plist());
        for partition in dmg.plist().partitions() {
            let table = partition.table()?;
            println!("{table:?}");
            println!("table checksum 0x{:x}", u32::from(table.checksum));
            for (i, chunk) in table.chunks.iter().enumerate() {
                println!("{i} {chunk:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn read_koly_trailer() -> Result<()> {
        let koly = KolyTrailer::read_from(&mut Cursor::new(DMG))?;
        //println!("{:#?}", koly);
        let mut bytes = [0; 512];
        koly.write_to(&mut &mut bytes[..])?;
        let koly2 = KolyTrailer::read_from(&mut Cursor::new(&bytes))?;
        assert_eq!(koly, koly2);
        Ok(())
    }

    #[test]
    fn only_read_dmg() -> Result<()> {
        let mut dmg = DmgReader::new(Cursor::new(DMG))?;
        print_dmg(&dmg)?;
        assert_eq!(
            UdifChecksum::new(dmg.data_checksum()?),
            dmg.koly().data_fork_digest
        );
        let mut buffer = vec![];
        let mut dmg2 = DmgWriter::new(Cursor::new(&mut buffer));
        for i in 0..dmg.plist().partitions().len() {
            let data = dmg.partition_data(i)?;
            let name = dmg.partition_name(i);
            dmg2.add_partition(name, &data)?;
        }
        dmg2.finish()?;
        let mut dmg2 = DmgReader::new(Cursor::new(buffer))?;
        print_dmg(&dmg2)?;
        assert_eq!(
            UdifChecksum::new(dmg2.data_checksum()?),
            dmg2.koly().data_fork_digest
        );
        for i in 0..dmg.plist().partitions().len() {
            let table = dmg.partition_table(i)?;
            let data = dmg.partition_data(i)?;
            let expected = u32::from(table.checksum);
            let calculated = crc32fast::hash(&data);
            assert_eq!(expected, calculated);
        }
        assert_eq!(dmg.koly().main_digest, dmg2.koly().main_digest);
        println!("data crc32 0x{:x}", u32::from(dmg.koly().data_fork_digest));
        println!("main crc32 0x{:x}", u32::from(dmg.koly().main_digest));
        Ok(())
    }

    #[test]
    fn read_dmg_partition_mbr() -> Result<()> {
        let mut dmg = DmgReader::new(Cursor::new(DMG))?;
        let mbr = dmg.partition_data(0)?;
        println!("{mbr:?}");
        let mbr = ProtectiveMBR::from_bytes(&mbr, LogicalBlockSize::Lb512)?;
        println!("{mbr:?}");
        Ok(())
    }

    #[test]
    fn read_dmg_partition_fat32() -> Result<()> {
        let mut dmg = DmgReader::new(Cursor::new(DMG))?;
        let fat32 = dmg.partition_data(1)?;
        let fs = FileSystem::new(Cursor::new(fat32), FsOptions::new())?;
        println!("volume: {}", fs.volume_label());
        for entry in fs.root_dir().iter() {
            let entry = entry?;
            println!("{}", entry.file_name());
        }
        Ok(())
    }

    #[test]
    fn checksum() -> Result<()> {
        let mut dmg = DmgReader::new(Cursor::new(DMG))?;
        assert_eq!(
            UdifChecksum::new(dmg.data_checksum()?),
            dmg.koly().data_fork_digest
        );
        for i in 0..dmg.plist().partitions().len() {
            let table = dmg.partition_table(i)?;
            let data = dmg.partition_data(i)?;
            let expected = u32::from(table.checksum);
            let calculated = crc32fast::hash(&data);
            assert_eq!(expected, calculated);
        }
        Ok(())
    }
}
