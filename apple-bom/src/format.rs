// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BOM file format primitives.
//!
//! Apple doesn't appear to have documented the BOM file format in any
//! publications or open source source code. So details of our understanding
//! of the BOM format could be wildly inaccurate.
//!
//! # File Format
//!
//! BOM files start with a header, [BomHeader]. The first 8 bytes of which
//! are magic `BOMStore`.
//!
//! BOM files logically consist of a collection of *blocks* and
//! *variables*. Each of these is defined by an *index*, the location of
//! which is defined in [BomHeader]. The *blocks* index is defined by
//! [BomBlocksIndex] and the *vars* index by [BomVarsIndex].
//!
//! Each *block* is simply an offset and length effectively denoting a
//! `&[u8]` from the source data. *Blocks* can be multiple types. These
//! types are represented by `BomBlock*` types in this module. The type
//! of each *block* is not explicitly captured by the blocks index. Rather,
//! block indices are referenced elsewhere and the block type is inferred
//! by the context of its reference.
//!
//! *Variables* define named content in the BOM, with each name denoting
//! special behavior. Each generic variable is defined by [BomVar] and
//! consists of a name and *block* index holding its data.
//!
//! # Block Types
//!
//! Here are the known block types:
//!
//! * [BomBlockBomInfo]
//! * [BomBlockFile]
//! * [BomBlockPathInfoIndex]
//! * [BomBlockPathRecord]
//! * [BomBlockPaths]
//! * [BomBlockTree]
//! * [BomBlockVIndex]
//!
//! See the documentation for each type for more details.
//!
//! # Variables
//!
//! This section documents what we know about each named variable.
//!
//! ## BomInfo
//!
//! Defines high-level information about the BOM. Its block data is [BomBlockBomInfo].
//!
//! ## Paths
//!
//! Defines the paths tracked by the BOM. Its block data is [BomBlockTree].
//!
//! ## HLIndex
//!
//! Unknown. Its block data is [BomBlockTree].
//!
//! ## VIndex
//!
//! Unknown. Its block data is [BomBlockVIndex].
//!
//! ## Size64
//!
//! Unknown. Its block data is [BomBlockTree].

use {
    crate::{BomPath, BomPathType, Error},
    scroll::{Pread, SizeWith},
    std::{borrow::Cow, collections::HashMap, ffi::CStr},
};

/// The header for a BOM file.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomHeader {
    /// Format magic. Always `BOMStore`
    pub magic: [u8; 8],

    /// File format version number.
    pub version: u32,

    /// Number of *blocks* in this BOM.
    pub number_of_blocks: u32,

    /// Start offset of blocks index relative to start of this header.
    pub blocks_index_offset: u32,

    /// Length of blocks index in bytes.
    pub blocks_index_length: u32,

    /// Start offset of variables index relative to start of this header.
    pub vars_index_offset: u32,

    /// Length of variables index in bytes.
    pub vars_index_length: u32,
}

impl BomHeader {
    /// Obtain the raw data holding the *blocks* index.
    pub fn blocks_index_data<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.blocks_index_offset as usize
            ..(self.blocks_index_offset + self.blocks_index_length) as usize]
    }

    /// Parse the *blocks* index.
    pub fn blocks_index(&self, data: &[u8]) -> Result<BomBlocksIndex, Error> {
        self.blocks_index_data(data)
            .pread_with::<BomBlocksIndex>(0, scroll::BE)
    }

    /// Obtain the raw data holding the *vars* index.
    pub fn vars_index_data<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.vars_index_offset as usize
            ..(self.vars_index_offset + self.vars_index_length) as usize]
    }

    /// Parse the *vars* index.
    pub fn vars_index(&self, data: &[u8]) -> Result<BomVarsIndex, Error> {
        self.vars_index_data(data)
            .pread_with::<BomVarsIndex>(0, scroll::BE)
    }
}

/// Defines *blocks* in the BOM file.
///
/// This is the data structure referred to by [BomHeader::blocks_index_offset] and
/// [BomHeader::blocks_index_length].
///
/// The 1st block appears to always be NULL (0 values in its entry).
///
/// The blocks count in this data structure and [BomHeader::number_of_blocks] may
/// disagree. The number of blocks in the file header appears to be the number of
/// populated blocks, not counting the initial NULL/empty/0 block. And the block
/// count in this data structure can be substantially larger than what is reported
/// by the file header.
#[derive(Clone, Default, Debug)]
pub struct BomBlocksIndex {
    /// The number of entries in this index.
    pub count: u32,

    /// The records defining individual blocks.
    pub blocks: Vec<BomBlocksEntry>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomBlocksIndex {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let count = data.gread_with::<u32>(offset, le)?;
        let mut blocks = Vec::with_capacity(count as usize);

        for _ in 0..count {
            blocks.push(data.gread_with::<BomBlocksEntry>(offset, le)?);
        }

        Ok((Self { count, blocks }, *offset))
    }
}

/// Defines the location of a *block*.
///
/// This type is part of [BomBlocksIndex].
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomBlocksEntry {
    /// Start offset of block data relative to start of file / [BomHeader].
    pub file_offset: u32,

    /// Length in bytes of block data.
    pub length: u32,
}

/// Describes an individual BOM variable.
///
/// A variable consists of a string name and pointer to the block index
/// holding its variable-specific data.
#[derive(Clone, Debug)]
pub struct BomVar {
    /// Index of block holding data for this variable.
    pub block_index: u32,

    /// Length of name. Does not include NULL terminator.
    pub name_length: u8,

    /// Name of variable.
    pub name: String,
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomVar {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let index = data.pread_with(0, le)?;
        let length = data.pread_with(4, le)?;

        let name_data = &data[5..5 + length as usize];
        let name = String::from_utf8(name_data.to_vec()).map_err(|_| Error::BadVariableString)?;

        Ok((
            Self {
                block_index: index,
                name_length: length,
                name,
            },
            5 + name_data.len(),
        ))
    }
}

/// Block type for `BomInfo` variable.
///
/// Describes high-level information about the BOM, notably the version and
/// number of paths.
#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct BomBlockBomInfo {
    /// BOM version.
    pub version: u32,

    /// Total number of paths tracked by this BOM.
    pub number_of_paths: u32,

    /// Number of [BomInfoEntry] records in this data structure.
    pub number_of_info_entries: u32,

    /// Further describes attributes of the BOM.
    pub entries: Vec<BomInfoEntry>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomBlockBomInfo {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let version = data.gread_with(offset, le)?;
        let number_of_paths = data.gread_with(offset, le)?;
        let number_of_info_entries = data.gread_with(offset, le)?;
        let mut entries = Vec::with_capacity(number_of_info_entries as usize);

        for _ in 0..number_of_info_entries {
            entries.push(data.gread_with(offset, le)?);
        }

        Ok((
            Self {
                version,
                number_of_paths,
                number_of_info_entries,
                entries,
            },
            *offset,
        ))
    }
}

/// Holds data records stored within [BomBlockBomInfo].
///
/// We do not currently know what the fields mean.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomInfoEntry {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

/// Block describing a named file.
#[derive(Clone, Debug)]
pub struct BomBlockFile<'a> {
    /// Internal path ID of parent path.
    ///
    /// `0` means no parent (this file exists at the root).
    pub parent_path_id: u32,

    /// The name of this file.
    ///
    /// Only the leaf file or directory name. i.e. the final component in a
    /// path.
    pub name: &'a CStr,
}

impl<'a> BomBlockFile<'a> {
    /// Obtain the file name as a [String].
    pub fn string_file_name(&self) -> String {
        self.name.to_string_lossy().to_string()
    }
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomBlockFile<'a> {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let parent = data.pread_with(0, le)?;
        let name = CStr::from_bytes_with_nul(&data[4..]).map_err(|_| Error::BadVariableString)?;

        Ok((
            Self {
                parent_path_id: parent,
                name,
            },
            data.len(),
        ))
    }
}

/// Block type describing a collection of paths.
///
/// Internally this stores a collection [BomPathsEntry] describing each tracked
/// path. These are pointers to [BomBlockPathInfoIndex] and [BomBlockFile] blocks
/// further describing each path.
///
/// Each logical path appears to have an internal numeric identifier uniquely
/// describing the path. This *path ID* is used for paths to refer to each
/// other. For example, [BomBlockFile] refers to its parent directory/path
/// via this ID.
#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct BomBlockPaths {
    /// Whether this is the root of a paths tree.
    pub is_root: u16,

    /// The number of paths tracked by this data structure.
    pub count: u16,

    /// Block index of [BomBlockPaths] that is after this one.
    pub next_paths_block_index: u32,

    /// Block index of [BomBlockPaths] that is before this one.
    pub previous_paths_block_index: u32,

    /// The paths tracked by this instance.
    pub paths: Vec<BomPathsEntry>,
}

impl BomBlockPaths {
    /// Resolve the [BomBlockFile] for a path at a given index.
    pub fn file_at<'a>(&self, bom: &'a ParsedBom, index: usize) -> Result<BomBlockFile<'a>, Error> {
        self.paths.get(index).ok_or(Error::BadIndex)?.file(bom)
    }

    /// Resolve the [BomBlockPathInfoIndex] for a path at a given index.
    pub fn path_info_at(
        &self,
        bom: &ParsedBom,
        index: usize,
    ) -> Result<BomBlockPathInfoIndex, Error> {
        self.paths.get(index).ok_or(Error::BadIndex)?.path_info(bom)
    }

    /// Resolve the internal path ID for a path at a given index.
    pub fn path_id_at(&self, bom: &ParsedBom, index: usize) -> Result<u32, Error> {
        Ok(self.path_info_at(bom, index)?.path_id)
    }

    /// Resolve the [BomBlockPathRecord] for a path at a given index.
    pub fn path_record_at<'a>(
        &self,
        bom: &'a ParsedBom,
        index: usize,
    ) -> Result<BomBlockPathRecord<'a>, Error> {
        self.path_info_at(bom, index)?.path_record(bom)
    }

    /// Resolve all meaningful path data for a path at a given index.
    pub fn path_entry_at<'a>(
        &self,
        bom: &'a ParsedBom,
        index: usize,
    ) -> Result<(u32, BomBlockFile<'a>, BomBlockPathRecord<'a>), Error> {
        let path_info = self.path_info_at(bom, index)?;
        let file = self.file_at(bom, index)?;
        let record = path_info.path_record(bom)?;

        Ok((path_info.path_id, file, record))
    }

    /// Obtain resolved records for each path defined on this instance.
    pub fn iter_path_entries<'a, 'b: 'a>(
        &'a self,
        bom: &'b ParsedBom,
    ) -> impl Iterator<Item = Result<(u32, BomBlockFile<'b>, BomBlockPathRecord<'b>), Error>> + 'a
    {
        self.paths
            .iter()
            .enumerate()
            .map(move |(i, _)| self.path_entry_at(bom, i))
    }

    /// Attempt to resolve records for a path given its internal path ID.
    pub fn path_entry_with_path_id<'a>(
        &self,
        bom: &'a ParsedBom,
        path_id: u32,
    ) -> Result<(BomBlockFile<'a>, BomBlockPathRecord<'a>), Error> {
        for entry in self.iter_path_entries(bom) {
            let (i, file, record) = entry?;

            if i == path_id {
                return Ok((file, record));
            }
        }

        Err(Error::BadIndex)
    }

    /// Obtain a [HashMap] mapping the internal path ID to its records.
    ///
    /// Since records refer to the internal path ID, this can help with
    /// batch lookups.
    pub fn path_entries_by_id<'a>(
        &self,
        bom: &'a ParsedBom,
    ) -> Result<HashMap<u32, (BomBlockFile<'a>, BomBlockPathRecord<'a>)>, Error> {
        let mut res = HashMap::with_capacity(self.paths.len());

        for entry in self.iter_path_entries(bom) {
            let (i, file, record) = entry?;
            res.insert(i, (file, record));
        }

        Ok(res)
    }

    /// Resolve the file name for an entry at an index.
    pub fn string_file_name_at(&self, bom: &ParsedBom, index: usize) -> Result<String, Error> {
        let file = self.file_at(bom, index)?;

        Ok(file.string_file_name())
    }

    fn resolve_full_filename(&self, bom: &ParsedBom, file: &BomBlockFile) -> Result<String, Error> {
        let mut file = file.clone();
        let mut filename = file.string_file_name();

        while file.parent_path_id != 0 {
            file = self.path_entry_with_path_id(bom, file.parent_path_id)?.0;
            filename = format!("{}/{}", file.string_file_name(), filename);
        }

        Ok(filename)
    }

    /// Attempt to resolve the full path for an entry at an index.
    ///
    /// This may fail if this instance is not the *root* paths block.
    pub fn full_path_at(&self, bom: &ParsedBom, index: usize) -> Result<String, Error> {
        self.resolve_full_filename(bom, &self.file_at(bom, index)?)
    }

    /// Attempt to resolve the full path for an entry given a path ID.
    pub fn full_path_with_path_id(&self, bom: &ParsedBom, path_id: u32) -> Result<String, Error> {
        self.resolve_full_filename(bom, &self.path_entry_with_path_id(bom, path_id)?.0)
    }

    /// Resolve each path to a [BomPath].
    ///
    /// This may fail if this isn't a root [BomBlockPaths].
    pub fn iter_bom_paths<'a, 'b: 'a>(
        &'a self,
        bom: &'b ParsedBom,
    ) -> impl Iterator<Item = Result<BomPath, Error>> + 'a {
        self.iter_path_entries(bom).map(move |entry| {
            let (_, file, record) = entry?;
            let filename = self.resolve_full_filename(bom, &file)?;

            BomPath::from_record(filename, &record)
        })
    }
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomBlockPaths {
    type Error = scroll::Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let is_root = data.gread_with::<u16>(offset, le)?;
        let count = data.gread_with::<u16>(offset, le)?;
        let forward = data.gread_with::<u32>(offset, le)?;
        let backward = data.gread_with::<u32>(offset, le)?;

        let mut paths = Vec::with_capacity(count as usize);
        for _ in 0..count {
            paths.push(data.gread_with::<BomPathsEntry>(offset, le)?);
        }

        Ok((
            Self {
                is_root,
                count,
                next_paths_block_index: forward,
                previous_paths_block_index: backward,
                paths,
            },
            *offset,
        ))
    }
}

/// Describes where to find metadata on a single path.
///
/// This type is contained within [BomBlockPaths].
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomPathsEntry {
    /// Block index of associated data structure.
    ///
    /// It appears this can refer to both a [BomBlockPathInfoIndex] or
    /// a [BomBlockPaths].
    ///
    /// TODO verify this.
    pub path_info_index: u32,

    /// Block index of [BomBlockFile].
    pub file_index: u32,
}

impl BomPathsEntry {
    /// Resolve the [BomBlockPathInfoIndex] this instance points to.
    pub fn path_info(&self, bom: &ParsedBom) -> Result<BomBlockPathInfoIndex, Error> {
        bom.block_as_path_info_index(self.path_info_index as _)
    }

    /// Resolve the [BomBlockFile] this instance points to.
    pub fn file<'a>(&self, bom: &'a ParsedBom) -> Result<BomBlockFile<'a>, Error> {
        bom.block_as_file(self.file_index as _)
    }
}

/// Block type describing a single path.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomBlockPathInfoIndex {
    /// Unique identifier for this path.
    ///
    /// This is not a block index.
    pub path_id: u32,

    /// Block index of [BomBlockPathRecord] holding metadata for this path.
    pub path_record_index: u32,
}

impl BomBlockPathInfoIndex {
    /// Resolve the [BomBlockPathRecord] this instance points to.
    pub fn path_record<'a>(&self, bom: &'a ParsedBom) -> Result<BomBlockPathRecord<'a>, Error> {
        bom.block_as_path_record(self.path_record_index as _)
    }
}

/// Block type defining low-level path information.
///
/// This is where most of the metadata defining a BOM path lives.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BomBlockPathRecord<'a> {
    /// The type of the path.
    ///
    /// See [crate::BomPathType] for definitions.
    pub path_type: u8,

    /// Unknown.
    pub a: u8,

    /// File architecture.
    ///
    /// Probably corresponds to value in Mach-O header.
    pub architecture: u16,

    /// File mode.
    pub mode: u16,

    /// UID of owner.
    pub user: u32,

    /// GID of owner.
    pub group: u32,

    /// Modified time in seconds since UNIX epoch.
    pub mtime: u32,

    /// Size in bytes.
    pub size: u32,

    /// Unknown.
    pub b: u8,

    /// CRC32 checksum or device type.
    pub checksum_or_type: u32,

    /// Length of link name.
    ///
    /// May be non-0 for non-link path records.
    ///
    /// Includes NULL terminator.
    pub link_name_length: u32,

    /// Link path name.
    pub link_name: Option<&'a CStr>,
}

impl<'a> BomBlockPathRecord<'a> {
    /// Obtain the link name of this record, if present.
    pub fn string_link_name(&self) -> Option<String> {
        self.link_name.map(|s| s.to_string_lossy().to_string())
    }
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomBlockPathRecord<'a> {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let path_type = data.gread_with(offset, le)?;
        let a = data.gread_with(offset, le)?;
        let architecture = data.gread_with(offset, le)?;
        let mode = data.gread_with(offset, le)?;
        let user = data.gread_with(offset, le)?;
        let group = data.gread_with(offset, le)?;
        let mtime = data.gread_with(offset, le)?;
        let size = data.gread_with(offset, le)?;
        let b = data.gread_with(offset, le)?;
        let checksum_or_type = data.gread_with(offset, le)?;
        let link_name_length = data.gread_with(offset, le)?;

        let link_name = if path_type == BomPathType::Link.into() && link_name_length > 0 {
            let link_name_data = &data[*offset..*offset + link_name_length as usize];
            Some(CStr::from_bytes_with_nul(link_name_data).map_err(|_| Error::BadVariableString)?)
        } else {
            None
        };

        Ok((
            Self {
                path_type,
                a,
                architecture,
                mode,
                user,
                group,
                mtime,
                size,
                b,
                checksum_or_type,
                link_name_length,
                link_name,
            },
            *offset,
        ))
    }
}

/// Block type for various variables describing a collection/tree of paths.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomBlockTree {
    /// Always `tree`.
    pub tree: [u8; 4],

    /// Version of this data structure.
    pub version: u32,

    /// Block index of [BomBlockPaths] describing paths.
    pub block_paths_index: u32,

    /// Block size. Always appears to be 4096.
    pub block_size: u32,

    /// Number of paths tracked by this tree.
    pub path_count: u32,

    /// Unknown.
    pub a: u8,
}

impl BomBlockTree {
    /// Resolve the [BomBlockPaths] this instance points to.
    pub fn paths(&self, bom: &ParsedBom) -> Result<BomBlockPaths, Error> {
        bom.block_as_paths(self.block_paths_index as _)
    }

    /// Resolve the [BomBlockPaths] that is the root of the tree.
    pub fn root_paths(&self, bom: &ParsedBom) -> Result<BomBlockPaths, Error> {
        let mut paths = self.paths(bom)?;

        while paths.is_root == 0 {
            let block_index = paths.paths.get(0).ok_or(Error::BadIndex)?.path_info_index;
            paths = bom.block_as_paths(block_index as _)?;
        }

        Ok(paths)
    }

    /// Obtain [BomPath] in this tree.
    pub fn bom_paths(&self, bom: &ParsedBom) -> Result<Vec<BomPath>, Error> {
        self.root_paths(bom)?
            .iter_bom_paths(bom)
            .collect::<Result<Vec<_>, Error>>()
    }
}

/// Block type for the `VIndex` variable data.
///
/// We don't know much about this data structure.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pread, SizeWith)]
pub struct BomBlockVIndex {
    /// Unknown.
    pub a: u32,

    /// Block index holding a [BomBlockTree].
    pub tree_block_index: u32,

    /// Unknown.
    pub b: u32,

    /// Unknown.
    pub c: u8,
}

impl BomBlockVIndex {
    /// Resolve the [BomBlockTree] this instance points to.
    pub fn tree(&self, bom: &ParsedBom) -> Result<BomBlockTree, Error> {
        bom.block_as_tree(self.tree_block_index as _)
    }
}

/// The collection of variables in a BOM file.
///
/// This structure is what [BomHeader::vars_index_offset] and
/// [BomHeader::vars_index_length] refers to.
#[derive(Clone, Debug)]
pub struct BomVarsIndex {
    /// Number of variables.
    pub count: u32,

    /// Records for each variable.
    pub vars: Vec<BomVar>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for BomVarsIndex {
    type Error = Error;

    fn try_from_ctx(data: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let count = data.gread_with::<u32>(offset, le)?;
        let mut vars = Vec::with_capacity(count as usize);

        for _ in 0..count {
            vars.push(data.gread_with::<BomVar>(offset, le)?);
        }

        Ok((Self { count, vars }, *offset))
    }
}

/// Parsed BOM data structure.
///
/// Instances hold references to the data they are backed by.
pub struct ParsedBom<'a> {
    /// Underlying data backing this BOM.
    pub data: Cow<'a, [u8]>,

    /// The file header.
    pub header: BomHeader,

    /// The blocks index.
    pub blocks: BomBlocksIndex,

    /// BOM variables.
    pub vars: BomVarsIndex,
}

impl<'a> ParsedBom<'a> {
    /// Parse BOM data into a data structure.
    ///
    /// Only the header and block and variable indices are parsed immediately.
    /// Everything else is lazily parsed.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = data.pread_with::<BomHeader>(0, scroll::BE)?;

        let blocks_index = header.blocks_index(data)?;
        let vars = header.vars_index(data)?;

        Ok(Self {
            data: Cow::Borrowed(data),
            header,
            blocks: blocks_index,
            vars,
        })
    }

    /// Convert to an instance that owns its backing data.
    pub fn to_owned(&self) -> ParsedBom<'static> {
        ParsedBom {
            data: Cow::Owned(self.data.clone().into_owned()),
            header: self.header,
            blocks: self.blocks.clone(),
            vars: self.vars.clone(),
        }
    }

    /// Attempt to locate a named variable.
    pub fn find_variable(&self, name: &str) -> Result<&BomVar, Error> {
        self.vars
            .vars
            .iter()
            .find(|v| v.name == name)
            .ok_or_else(|| Error::NoVar(name.to_string()))
    }

    /// Attempt to resolve the [BomBlockBomInfo] for this instance.
    pub fn bom_info(&self) -> Result<BomBlockBomInfo, Error> {
        let var = self.find_variable("BomInfo")?;

        self.block_as_bom_info(var.block_index as _)
    }

    pub fn hl_index(&self) -> Result<Vec<BomPath>, Error> {
        let var = self.find_variable("HLIndex")?;
        let tree = self.block_as_tree(var.block_index as _)?;

        tree.bom_paths(self)
    }

    pub fn paths(&self) -> Result<Vec<BomPath>, Error> {
        let index = self.find_variable("Paths")?;
        let tree = self.block_as_tree(index.block_index as _)?;

        tree.bom_paths(self)
    }

    /// Resolve the Size64 tree.
    pub fn size64(&self) -> Result<Vec<BomPath>, Error> {
        let var = self.find_variable("Size64")?;
        let tree = self.block_as_tree(var.block_index as _)?;

        tree.bom_paths(self)
    }

    /// Resolve the V Index.
    pub fn vindex(&self) -> Result<Vec<BomPath>, Error> {
        let var = self.find_variable("VIndex")?;
        let index = self.block_as_vindex(var.block_index as _)?;
        let tree = index.tree(self)?;

        tree.bom_paths(self)
    }

    /// Resolve the raw data backing a block given a block index.
    pub fn block_data(&self, index: usize) -> Result<&[u8], Error> {
        let entry = self.blocks.blocks.get(index).ok_or(Error::BadIndex)?;

        Ok(&self.data[entry.file_offset as usize..(entry.file_offset + entry.length) as usize])
    }

    /// Attempt to resolve a block at an index as a [BomBlockBomInfo].
    pub fn block_as_bom_info(&self, index: usize) -> Result<BomBlockBomInfo, Error> {
        self.block_data(index)?.pread_with(0, scroll::BE)
    }

    /// Attempt to resolve a block at an index as a [BomBlockFile].
    pub fn block_as_file(&self, index: usize) -> Result<BomBlockFile<'_>, Error> {
        self.block_data(index)?.pread_with(0, scroll::BE)
    }

    /// Attempt to resolve a block at an index as a [BomBlockPathInfoIndex].
    pub fn block_as_path_info_index(&self, index: usize) -> Result<BomBlockPathInfoIndex, Error> {
        Ok(self.block_data(index)?.pread_with(0, scroll::BE)?)
    }

    /// Attempt to resolve a block at an index as a [BomBlockPathRecord].
    pub fn block_as_path_record(&self, index: usize) -> Result<BomBlockPathRecord, Error> {
        self.block_data(index)?.pread_with(0, scroll::BE)
    }

    /// Attempt to resolve a block at an index as a [BomBlockPaths].
    pub fn block_as_paths(&self, index: usize) -> Result<BomBlockPaths, Error> {
        let data = self.block_data(index)?;
        Ok(data.pread_with(0, scroll::BE)?)
    }

    /// Attempt to resolve a black at an index as a [BomBlockTree].
    pub fn block_as_tree(&self, index: usize) -> Result<BomBlockTree, Error> {
        let data = self.block_data(index)?;
        Ok(data.pread_with(0, scroll::BE)?)
    }

    /// Attempt to resolve a block at an index as a [BomBlockVIndex].
    pub fn block_as_vindex(&self, index: usize) -> Result<BomBlockVIndex, Error> {
        Ok(self.block_data(index)?.pread_with(0, scroll::BE)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PYTHON_DATA: &[u8] = include_bytes!("testdata/python-applications.bom");

    #[test]
    fn parse_python() -> Result<(), Error> {
        let bom = crate::format::ParsedBom::parse(PYTHON_DATA)?;

        bom.bom_info()?;

        // Forces recursive parsing
        for _ in bom.hl_index()? {}
        for _ in bom.paths()? {}
        for _ in bom.size64()? {}
        for _ in bom.vindex()? {}

        let root = bom.paths()?.into_iter().find(|p| p.path() == ".").unwrap();
        assert_eq!(root.symbolic_mode(), "drwxr-xr-x");

        let readme = bom
            .paths()?
            .into_iter()
            .find(|p| p.path() == "./Python 3.9/ReadMe.rtf")
            .unwrap();
        assert_eq!(readme.symbolic_mode(), "-rw-r--r--");

        Ok(())
    }
}
