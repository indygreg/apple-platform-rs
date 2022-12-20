// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {
    crate::{
        error::Error,
        format::{
            BomBlock, BomBlockBomInfo, BomBlockFile, BomBlockPathInfoIndex, BomBlockPathRecord,
            BomBlockPathRecordPointer, BomBlockPaths, BomBlockTree, BomBlockTreePointer,
            BomBlockVIndex, BomBlocksEntry, BomBlocksIndex, BomHeader, BomInfoEntry, BomPathsEntry,
            BomVar, BomVarsIndex,
        },
        path::{BomPath, BomPathType},
    },
    chrono::{DateTime, Utc},
    scroll::IOwrite,
    simple_file_manifest::{S_IFDIR, S_IRGRP, S_IROTH, S_IRUSR, S_IWUSR, S_IXGRP, S_IXUSR},
    std::{
        borrow::Cow,
        collections::{BTreeMap, HashMap},
        ffi::CString,
        io::{Cursor, Read, Write},
        path::Path,
    },
};

fn crc32_path(path: &Path) -> std::io::Result<(u32, usize)> {
    let mut h = crc32fast::Hasher::new();

    let mut fh = std::fs::File::open(path)?;
    let mut buffer = [0u8; 32768];
    let mut file_size = 0;

    loop {
        let bytes_read = fh.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        file_size += bytes_read;
        h.update(&buffer[0..bytes_read]);
    }

    Ok((h.finalize(), file_size))
}

fn crc32_data(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn validate_bom_path(s: &str) -> Result<(), Error> {
    if s.starts_with('.') {
        Err(Error::BadPath(s.to_string(), "path cannot start with ."))
    } else if s.starts_with('/') {
        Err(Error::BadPath(s.to_string(), "path cannot start with /"))
    } else if s.contains('\\') {
        Err(Error::BadPath(s.to_string(), "path cannot contain \\"))
    } else {
        Ok(())
    }
}

/// Entity for constructing new BOM data structures.
#[derive(Clone, Debug)]
pub struct BomBuilder {
    /// Paths to materialize.
    ///
    /// Directories are not tracked explicitly. Rather they are derived
    /// at BOM generation time.
    paths: BTreeMap<String, BomPath>,

    default_mtime: DateTime<Utc>,

    default_uid: u32,
    default_gid: u32,

    default_mode_file: u16,
    default_mode_dir: u16,
}

impl Default for BomBuilder {
    fn default() -> Self {
        Self {
            paths: Default::default(),
            default_mtime: Utc::now(),
            default_uid: 0,
            default_gid: 0,
            // -rw-r--r--
            default_mode_file: (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) as u16,
            // drwxr-xr-x
            default_mode_dir: (S_IFDIR
                | S_IRUSR
                | S_IWUSR
                | S_IXUSR
                | S_IRGRP
                | S_IXGRP
                | S_IROTH
                | S_IXGRP) as u16,
        }
    }
}

impl BomBuilder {
    fn default_file_path(&self) -> BomPath {
        BomPath {
            path_type: BomPathType::File,
            path: "".to_string(),
            file_mode: self.default_mode_file,
            user_id: self.default_uid,
            group_id: self.default_gid,
            mtime: self.default_mtime,
            size: 0,
            crc32: None,
            link_name: None,
        }
    }

    /// Set the default file mode to use for files.
    pub fn default_mode_file(&mut self, mode: u16) {
        self.default_mode_file = mode;
    }

    /// Set the default file mode to use for directories.
    pub fn default_mode_directory(&mut self, mode: u16) {
        self.default_mode_dir = mode;
    }

    /// Set the default user ID (UID).
    pub fn default_user_id(&mut self, uid: u32) {
        self.default_uid = uid;
    }

    /// Set the default group ID (GID).
    pub fn default_group_id(&mut self, gid: u32) {
        self.default_gid = gid;
    }

    /// Set the default modified time.
    pub fn default_mtime(&mut self, mtime: DateTime<Utc>) {
        self.default_mtime = mtime;
    }

    /// Add a file to this BOM with file content derived from a filesystem path.
    ///
    /// A mutable reference to the just-added entry is returned to allow
    /// for further customization.
    pub fn add_file_from_path(
        &mut self,
        bom_path: impl ToString,
        path: impl AsRef<Path>,
    ) -> Result<&mut BomPath, Error> {
        let bom_path = bom_path.to_string();
        validate_bom_path(&bom_path)?;
        let path = path.as_ref();

        let (crc32, file_size) = crc32_path(path)?;

        let mut path = self.default_file_path();
        path.path = bom_path.clone();
        path.size = file_size;
        path.crc32 = Some(crc32);

        self.paths.insert(bom_path.clone(), path);

        Ok(self.paths.get_mut(&bom_path).unwrap())
    }

    /// Add a file to this BOM with content specified from a slice.
    ///
    /// A mutable reference to the just-added entry is returned to allow
    /// for further customization.
    pub fn add_file_from_data(
        &mut self,
        bom_path: impl ToString,
        data: impl AsRef<[u8]>,
    ) -> Result<&mut BomPath, Error> {
        let bom_path = bom_path.to_string();
        validate_bom_path(&bom_path)?;

        let data = data.as_ref();

        let mut path = self.default_file_path();
        path.path = bom_path.clone();
        path.size = data.len();
        path.crc32 = Some(crc32_data(data));

        self.paths.insert(bom_path.clone(), path);

        Ok(self.paths.get_mut(&bom_path).unwrap())
    }

    /// Serialize the BOM data structure to bytes.
    pub fn build_bom(&self) -> Result<Vec<u8>, Error> {
        // Index is the path ID. Value is the filename as stored in the BOM.
        let mut path_to_path_id = HashMap::with_capacity(self.paths.len() + 1);
        let mut records = Vec::with_capacity(self.paths.len() + 1);

        // Root directory is special.
        path_to_path_id.insert(".".to_string(), 1u32);

        let path_record = BomBlockPathRecord {
            path_type: BomPathType::Directory.into(),
            a: 1,
            architecture: 1,
            mode: 0,
            user: 0,
            group: 0,
            mtime: 0,
            size: 0,
            b: 1,
            checksum_or_type: 0,
            link_name_length: 0,
            link_name: None,
        };
        let file = BomBlockFile {
            parent_path_id: 0,
            name: Cow::from(CString::new(b".\0".to_vec()).expect("string is null terminated")),
        };

        records.push((1u32, path_record, file));

        for (index_path, entry) in &self.paths {
            // We need to emit parent paths before the file itself. So split
            // on directory separator and iterate on all parent paths.
            let path_parts = index_path.split('/').collect::<Vec<_>>();

            for i in 1..path_parts.len() {
                let parent_parts = &path_parts[0..i];
                let path = format!("./{}", &parent_parts.join("/"));

                // Already emitted it. Nothing to do here.
                if path_to_path_id.contains_key(&path) {
                    continue;
                }

                let path_id = path_to_path_id.len() as u32 + 1;

                let parent_path = &path[0..path.rfind('/').expect("path should always have /")];
                let parent_path_id = *path_to_path_id
                    .get(parent_path)
                    .expect("parent path should always be present");

                let path_record = BomBlockPathRecord {
                    path_type: BomPathType::Directory.into(),
                    a: 1,
                    architecture: 15,
                    mode: self.default_mode_dir,
                    user: self.default_uid,
                    group: self.default_gid,
                    mtime: self.default_mtime.timestamp() as u32,
                    size: 0,
                    b: 1,
                    checksum_or_type: 0,
                    link_name_length: 0,
                    link_name: None,
                };

                let mut path_cstring = Vec::<u8>::with_capacity(path.as_bytes().len());
                path_cstring.extend(path.as_bytes());
                path_cstring.push(0);
                let path_cstring =
                    CString::new(path_cstring).expect("C string should be well formed");

                let file = BomBlockFile {
                    parent_path_id,
                    name: Cow::from(path_cstring),
                };

                path_to_path_id.insert(path, path_id);
                records.push((path_id, path_record, file));
            }

            // Now handle the file entry itself.
            let path = format!("./{index_path}");
            let parent_path = &path[0..path.rfind('/').expect("/ should appear in path")];
            let parent_path_id = *path_to_path_id
                .get(parent_path)
                .expect("parent path should be present");
            let path_id = path_to_path_id.len() as u32 + 1;

            let mut path_cstring = Vec::<u8>::with_capacity(path.as_bytes().len() + 1);
            path_cstring.extend(path.as_bytes());
            path_cstring.push(0);
            let path_cstring = CString::new(path_cstring).expect("should be valid C string");

            let path_record = BomBlockPathRecord {
                path_type: entry.path_type().into(),
                a: 1,
                architecture: 15,
                mode: entry.file_mode(),
                user: entry.user_id(),
                group: entry.group_id(),
                mtime: entry.modified_time().timestamp() as _,
                size: entry.size() as _,
                b: 1,
                checksum_or_type: entry.crc32().unwrap_or(0),
                link_name_length: if let Some(link_name) = entry.link_name() {
                    link_name.as_bytes().len() as u32 + 1
                } else {
                    0
                },
                link_name: entry.link_name_cstring().map(Cow::from),
            };

            let file = BomBlockFile {
                parent_path_id,
                name: Cow::from(path_cstring),
            };

            path_to_path_id.insert(path, path_id);
            records.push((path_id, path_record, file));
        }

        // We now have all our paths assembled. It is now time to produce the blocks.
        let mut blocks = vec![];
        let mut paths_entries = Vec::with_capacity(records.len());

        // Block at index 0 is the special empty block.
        blocks.push(BomBlock::Empty);

        // By convention, block at index 1 is BomInfo.
        blocks.push(BomBlock::BomInfo(BomBlockBomInfo {
            version: 1,
            // 1 extra record for the null path.
            number_of_paths: records.len() as u32 + 1,
            number_of_info_entries: 3,
            entries: vec![
                // We aren't sure what these values mean. But these are the values
                // written by Apple tooling.
                BomInfoEntry {
                    a: 0,
                    b: 0,
                    c: 8546296,
                    d: 0,
                },
                BomInfoEntry {
                    a: 16777223,
                    b: 0,
                    c: 37959280,
                    d: 0,
                },
                BomInfoEntry {
                    a: 16777228,
                    b: 0,
                    c: 25620800,
                    d: 0,
                },
            ],
        }));

        let mut vars_index = BomVarsIndex {
            count: 1,
            vars: vec![BomVar::new(blocks.len() as _, "BomInfo")?],
        };

        // If we wanted to adhere to the order in Apple's tooling, we would emit
        // data structures referred to by the BOM variables next. But since
        // order doesn't appear to matter, we take the simpler approach and emit
        // them last, after all paths entries.

        for (path_id, path_record, file) in records {
            let path_record_index = blocks.len() as u32;
            blocks.push(BomBlock::PathRecord(path_record));
            let file_index = blocks.len() as u32;
            blocks.push(BomBlock::File(file));
            let path_info_index = blocks.len() as u32;
            blocks.push(BomBlock::PathInfoIndex(BomBlockPathInfoIndex {
                path_id,
                path_record_index,
            }));

            paths_entries.push(BomPathsEntry {
                block_index: path_info_index,
                file_index,
            });
        }

        // There are additional Tree, Paths, PathRecordPointer, and TreePointer
        // blocks for each tracked path. Why these exist, we're not sure. But we
        // provide them for parity with Apple tooling.
        let path_record_indices = blocks
            .iter()
            .enumerate()
            .filter_map(|(i, block)| {
                if matches!(block, BomBlock::PathRecord(_)) {
                    Some(i as u32)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for block_path_record_index in path_record_indices {
            let block_tree_index = blocks.len() as u32;
            blocks.push(BomBlock::Tree(BomBlockTree {
                block_paths_index: blocks.len() as u32 + 1,
                block_size: 64,
                ..Default::default()
            }));
            blocks.push(BomBlock::Paths(BomBlockPaths {
                is_path_info: 1,
                ..Default::default()
            }));
            blocks.push(BomBlock::PathRecordPointer(BomBlockPathRecordPointer {
                block_path_record_index,
            }));
            blocks.push(BomBlock::TreePointer(BomBlockTreePointer {
                block_tree_index,
            }));
        }

        // The Paths variable points to a Tree + Paths.
        //
        // The Paths blocks are a bit complicated. The primary Paths is a pointer
        // to another one. And, due to the 4096 block size limit, there can be multiple
        // Paths blocks.
        const PATHS_BLOCK_SIZE: u32 = 4096;

        blocks.push(BomBlock::Tree(BomBlockTree {
            block_paths_index: blocks.len() as u32 + 1,
            block_size: PATHS_BLOCK_SIZE,
            path_count: paths_entries.len() as u32,
            ..Default::default()
        }));
        vars_index.count += 1;
        vars_index
            .vars
            .push(BomVar::new(blocks.len() as _, "Paths")?);

        // Determine final set of Paths blocks holding meaningful records.
        let mut paths_blocks = vec![];
        let mut paths_block = BomBlockPaths {
            is_path_info: 1,
            ..Default::default()
        };
        for path_entry in paths_entries {
            paths_block.count += 1;
            paths_block.paths.push(path_entry);

            let remaining_bytes = PATHS_BLOCK_SIZE - 12 - 8 * paths_block.count as u32;

            // Running out of room. Flush block.
            if remaining_bytes < 16 {
                paths_blocks.push(paths_block.clone());
                paths_block = BomBlockPaths {
                    is_path_info: 1,
                    ..Default::default()
                };
            }
        }

        if paths_block.count > 0 || paths_blocks.is_empty() {
            paths_blocks.push(paths_block);
        }

        // 1st Paths block is a pointer to meaningful one.
        blocks.push(BomBlock::Paths(BomBlockPaths {
            is_path_info: 0,
            count: 1,
            paths: vec![BomPathsEntry {
                block_index: blocks.len() as u32 + 1,
                file_index: if let Some(entry) = paths_blocks[0].paths.get(0) {
                    entry.file_index
                } else {
                    0
                },
            }],
            ..Default::default()
        }));

        for (i, paths) in paths_blocks.iter().enumerate() {
            blocks.push(BomBlock::Paths(BomBlockPaths {
                is_path_info: paths.is_path_info,
                count: paths.count,
                next_paths_block_index: if i == paths_blocks.len() - 1 {
                    0
                } else {
                    blocks.len() as u32 + 2
                },
                previous_paths_block_index: if i == 0 { 0 } else { blocks.len() as u32 },
                paths: paths.paths.clone(),
            }));
        }

        // Add records for other variables.

        // HLIndex is Tree + Paths.
        blocks.push(BomBlock::Tree(BomBlockTree {
            block_paths_index: blocks.len() as u32 + 1,
            block_size: PATHS_BLOCK_SIZE,
            ..Default::default()
        }));
        vars_index.count += 1;
        vars_index
            .vars
            .push(BomVar::new(blocks.len() as _, "HLIndex")?);
        blocks.push(BomBlock::Paths(BomBlockPaths {
            is_path_info: 1,
            ..Default::default()
        }));

        // VIndex is VIndex + Tree + Paths.
        blocks.push(BomBlock::VIndex(BomBlockVIndex {
            a: 1,
            tree_block_index: blocks.len() as u32 + 1,
            b: 0,
            c: 0,
        }));
        vars_index.count += 1;
        vars_index
            .vars
            .push(BomVar::new(blocks.len() as _, "VIndex")?);
        blocks.push(BomBlock::Tree(BomBlockTree {
            block_paths_index: blocks.len() as u32 + 1,
            block_size: PATHS_BLOCK_SIZE,
            ..Default::default()
        }));
        blocks.push(BomBlock::Paths(BomBlockPaths {
            is_path_info: 1,
            ..Default::default()
        }));

        // Size64 is Tree + Paths.
        blocks.push(BomBlock::Tree(BomBlockTree {
            block_paths_index: blocks.len() as u32 + 1,
            block_size: PATHS_BLOCK_SIZE,
            ..Default::default()
        }));
        vars_index.count += 1;
        vars_index
            .vars
            .push(BomVar::new(blocks.len() as _, "Size64")?);
        blocks.push(BomBlock::Paths(BomBlockPaths {
            is_path_info: 1,
            ..Default::default()
        }));

        // Now that we've assembled all the blocks as data structures, it is time to write
        // them out.
        //
        // The header contains offsets and sizes of variable length data, which we won't
        // know until we produced it. Furthermore, the blocks index refers to file level
        // offsets. There's kind of a chicken and egg problem here. We side step it by
        // starting blocks data at a fixed file offset, giving plenty of room for the
        // file header.
        const BLOCK_DATA_FILE_OFFSET: u32 = 512;

        let mut blocks_index = BomBlocksIndex::default();
        let mut blocks_writer = Cursor::new(Vec::<u8>::new());

        for block in &blocks {
            let start_offset = blocks_writer.position();
            block.write(&mut blocks_writer)?;
            let end_offset = blocks_writer.position();

            blocks_index.count += 1;
            blocks_index.blocks.push(BomBlocksEntry {
                file_offset: BLOCK_DATA_FILE_OFFSET + start_offset as u32,
                length: (end_offset - start_offset) as _,
            });
        }

        let blocks_data = blocks_writer.into_inner();
        let vars_index_data = vars_index.to_vec()?;
        let blocks_index_data = blocks_index.to_vec()?;

        // The vars index is small. We can put it after the header.
        const VARS_INDEX_OFFSET: u32 = 128;

        // The blocks index goes after the blocks data. We align on 64 byte boundary
        // because why not.
        let blocks_index_offset = BLOCK_DATA_FILE_OFFSET
            + blocks_data.len() as u32
            + (64 - blocks_data.len() % 64) as u32;

        let header = BomHeader {
            magic: *b"BOMStore",
            version: 1,
            number_of_blocks: blocks.len() as _,
            blocks_index_offset,
            blocks_index_length: blocks_index_data.len() as _,
            vars_index_offset: VARS_INDEX_OFFSET,
            vars_index_length: vars_index_data.len() as _,
        };

        // We have all the requisite parts. Time to write it.
        let mut writer = Cursor::new(Vec::<u8>::new());
        writer.iowrite_with(header, scroll::BE)?;

        // Pad to vars index.
        for _ in 0..VARS_INDEX_OFFSET - writer.position() as u32 {
            writer.write_all(b"\0")?;
        }

        writer.write_all(&vars_index_data)?;

        // Pad to blocks data.
        for _ in 0..BLOCK_DATA_FILE_OFFSET - writer.position() as u32 {
            writer.write_all(b"\0")?;
        }

        writer.write_all(&blocks_data)?;

        // Pad to blocks index.
        for _ in 0..blocks_index_offset - writer.position() as u32 {
            writer.write_all(b"\0")?;
        }

        writer.write_all(&blocks_index_data)?;

        Ok(writer.into_inner())
    }
}
