// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Filesystem reading functionality.

use crate::block::BlockReader;
use crate::btree::{BTree, NodeKey, NodeValue};
use crate::data_stream::{FileExtentRecordKeyParsed, FileExtentRecordValueParsed};
use crate::error::{ApfsError, Result};
use crate::filesystem::{
    DirectoryEntryRecordValueParsed, ExtendedAttributeRecordKeyParsed,
    ExtendedAttributeRecordValueParsed, ExtendedAttributeValue, FileModeRaw, FileSystemKeyParsed,
    FileSystemObjectType, FileSystemRecord, InodeRecord, InodeRecordKeyParsed,
    InodeRecordValueParsed, INODE_ROOT_DIRECTORY, INODE_ROOT_DIRECTORY_PARENT,
};
use crate::object_map::ObjectMap;
use crate::read::file_extent::FileExtentReader;
use apfs_types::ParsedDiskStruct;
use log::{debug, trace, warn};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use xattr::FileExt;

use apfs_types::pod::ApfsString;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Obtains the character representing the file type.
///
/// For use in printing the human friendly file mode mask.
pub fn file_mode_text_mask_type(mode: FileModeRaw) -> char {
    if mode.contains(FileModeRaw::S_IFIFO) {
        'p'
    } else if mode.contains(FileModeRaw::S_IFCHR) {
        'c'
    } else if mode.contains(FileModeRaw::S_IFDIR) {
        'd'
    } else if mode.contains(FileModeRaw::S_IFBLK) {
        'b'
    } else if mode.contains(FileModeRaw::S_IFREG) {
        '-'
    } else if mode.contains(FileModeRaw::S_IFLNK) {
        'l'
    } else if mode.contains(FileModeRaw::S_IFSOCK) {
        's'
    } else if mode.contains(FileModeRaw::S_IFWHT) {
        'w'
    } else {
        '-'
    }
}

/// Obtain the `rwx` text mask for the user/owner bits.
pub fn file_mode_text_mask_owner(mode: FileModeRaw) -> [char; 3] {
    let r = if mode.contains(FileModeRaw::S_IRUSR) {
        'r'
    } else {
        '-'
    };
    let w = if mode.contains(FileModeRaw::S_IWUSR) {
        'w'
    } else {
        '-'
    };
    let x = if mode.contains(FileModeRaw::S_IXUSR) {
        'x'
    } else {
        '-'
    };

    [r, w, x]
}

/// Obtain the `rwx` text mask for the group bits.
pub fn file_mode_text_mask_group(mode: FileModeRaw) -> [char; 3] {
    let r = if mode.contains(FileModeRaw::S_IRGRP) {
        'r'
    } else {
        '-'
    };
    let w = if mode.contains(FileModeRaw::S_IWGRP) {
        'w'
    } else {
        '-'
    };
    let x = if mode.contains(FileModeRaw::S_IXGRP) {
        'x'
    } else {
        '-'
    };

    [r, w, x]
}

/// Obtain the `rwx` text mask for the other bits.
pub fn file_mode_text_mask_other(mode: FileModeRaw) -> [char; 3] {
    let r = if mode.contains(FileModeRaw::S_IROTH) {
        'r'
    } else {
        '-'
    };
    let w = if mode.contains(FileModeRaw::S_IWOTH) {
        'w'
    } else {
        '-'
    };
    let x = if mode.contains(FileModeRaw::S_IXOTH) {
        'x'
    } else {
        '-'
    };

    [r, w, x]
}

/// Obtain a human friendly string representing the file mode.
///
/// e.g. `drwxrwxrwx`.
pub fn file_mode_text_mask(mode: FileModeRaw) -> String {
    std::iter::once(file_mode_text_mask_type(mode))
        .chain(file_mode_text_mask_owner(mode).into_iter())
        .chain(file_mode_text_mask_group(mode).into_iter())
        .chain(file_mode_text_mask_other(mode).into_iter())
        .collect()
}

#[cfg(unix)]
fn reconcile_permissions(
    _existing: std::fs::Permissions,
    inode: &InodeRecord,
) -> std::fs::Permissions {
    std::fs::Permissions::from_mode(inode.value.mode().bits() as u32)
}

#[cfg(windows)]
fn reconcile_permissions(
    mut existing: std::fs::Permissions,
    inode: &InodeRecord,
) -> std::fs::Permissions {
    if !inode
        .value
        .mode
        .contains(FileModeRaw::S_IWUSR | FileModeRaw::S_IWGRP | FileModeRaw::S_IWOTH)
    {
        existing.set_readonly(true);
    }

    existing
}

/// Holds filesystem records for a single logical filesystem entity.
#[derive(Clone, Debug)]
pub struct FilesystemRecordCollection {
    records: Vec<FileSystemRecord>,
}

impl FilesystemRecordCollection {
    /// Obtain the inode record.
    pub fn inode(&self) -> Option<&InodeRecord> {
        self.records.iter().find_map(|r| {
            if let FileSystemRecord::Inode(v) = r {
                Some(v)
            } else {
                None
            }
        })
    }

    /// Obtain the file extent records.
    ///
    /// Each file extent describes a block range holding a segment of the file.
    /// Often there is just a single extent. But there can be multiple extents
    /// chained together.
    pub fn file_extents(
        &self,
    ) -> impl Iterator<Item = (&FileExtentRecordKeyParsed, &FileExtentRecordValueParsed)> + '_ {
        self.records.iter().filter_map(|r| {
            if let FileSystemRecord::FileExtent(k, v) = r {
                Some((k, v))
            } else {
                None
            }
        })
    }

    /// Iterate over extended attribute records in this entry.
    pub fn extended_attributes(
        &self,
    ) -> impl Iterator<
        Item = (
            &ExtendedAttributeRecordKeyParsed,
            &ExtendedAttributeRecordValueParsed,
        ),
    > + '_ {
        self.records.iter().filter_map(|r| {
            if let FileSystemRecord::ExtendedAttribute(k, v) = r {
                Some((k, v))
            } else {
                None
            }
        })
    }

    /// Obtain all directory entries in this record.
    ///
    /// Records are returned in their original B-tree order, which is likely
    /// sorted by file id / inode number.
    pub fn directory_entries(
        &self,
    ) -> impl Iterator<Item = Result<(&ApfsString, &DirectoryEntryRecordValueParsed)>> + '_ {
        self.records.iter().filter_map(|r| match r {
            FileSystemRecord::DirectoryEntry(k, v) => {
                let res = match k.trailing_data() {
                    Ok(name) => Ok((name, v)),
                    Err(err) => Err(ApfsError::from(err)),
                };

                Some(res)
            }
            FileSystemRecord::DirectoryEntryHashed(k, v) => {
                let res = match k.trailing_data() {
                    Ok(name) => Ok((name, v)),
                    Err(err) => Err(ApfsError::from(err)),
                };

                Some(res)
            }
            _ => None,
        })
    }

    /// Whether this record has file data.
    pub fn has_file_content(&self) -> bool {
        if let Some(inode) = self.inode() {
            matches!(inode.data_stream(), Ok(Some(_))) && self.file_extents().next().is_some()
        } else {
            false
        }
    }

    /// Obtain a reader for file content.
    ///
    /// This constructs a reader from file extent records and inode / data stream
    /// metadata.
    pub fn file_reader<'a, R: BlockReader>(&self, reader: &'a R) -> Result<impl Read + 'a> {
        let inode = self.inode().ok_or(ApfsError::FileNoInode)?;
        let dstream = inode.data_stream()?.ok_or(ApfsError::InodeNoDataStream)?;
        debug!(
            "creating file reader for inode {} spanning {} bytes",
            inode.key.header().id(),
            dstream.size_bytes()
        );

        let reader = FileExtentReader::new(reader, self.file_extents());

        Ok(reader.take(dstream.size_bytes()))
    }

    /// Write this filesystem record to the specified local filesystem path.
    ///
    /// Effectively copies the record to another filesystem.
    ///
    /// Implementation is best effort and not feature complete.
    pub fn write_path<'a, R: BlockReader>(&self, reader: &'a R, dest_path: &Path) -> Result<()> {
        let inode = self.inode().ok_or(ApfsError::FileNoInode)?;

        let mode = inode.value.mode();

        // Ensure parent exists.
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let fh = match mode & FileModeRaw::S_IFMT {
            x if x == FileModeRaw::S_IFDIR => {
                trace!("creating directory {}", dest_path.display());
                std::fs::create_dir(dest_path)?;

                std::fs::File::open(dest_path)?
            }
            x if x == FileModeRaw::S_IFREG => {
                trace!("creating file {}", dest_path.display());
                let mut reader = self.file_reader(reader)?;
                let mut fh = std::fs::File::create(dest_path)?;
                std::io::copy(&mut reader, &mut fh)?;
                fh
            }
            _ => {
                return Err(ApfsError::Unimplemented("writing non file/directory inode"));
            }
        };

        let metadata = fh.metadata()?;

        let permissions = reconcile_permissions(metadata.permissions(), inode);
        fh.set_permissions(permissions)?;

        let epoch = std::time::SystemTime::UNIX_EPOCH;

        let times = std::fs::FileTimes::new()
            .set_accessed(epoch + std::time::Duration::from_nanos(inode.value.access_time().get()))
            .set_modified(
                epoch + std::time::Duration::from_nanos(inode.value.modification_time().get()),
            );
        fh.set_times(times)?;

        // TODO chown/chgrp

        // Best effort preservation of extended attributes.
        if xattr::SUPPORTED_PLATFORM {
            for (k, v) in self.extended_attributes() {
                let name = k.trailing_data()?;

                trace!("setting xattr {} on {}", name.as_str(), dest_path.display());

                match v.trailing_data()? {
                    ExtendedAttributeValue::Embedded(data) => {
                        if let Err(err) = fh.set_xattr(name.as_str(), data.as_ref()) {
                            warn!(
                                "error setting extended attribute {} on {}: {}",
                                name.as_str(),
                                dest_path.display(),
                                err
                            );
                        }
                    }
                    ExtendedAttributeValue::StreamId(_) => {
                        return Err(ApfsError::Unimplemented(
                            "extended attributes in data stream",
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Interface to a filesystem B-tree.
pub struct FilesystemTreeReader<'a, R: BlockReader, O: ObjectMap> {
    inner: BTree,
    reader: &'a R,
    object_map: &'a O,
}

impl<'a, R: BlockReader, O: ObjectMap> FilesystemTreeReader<'a, R, O> {
    /// Construct an instance from a [BTree].
    pub fn new(tree: BTree, reader: &'a R, object_map: &'a O) -> Self {
        Self {
            inner: tree,
            reader,
            object_map,
        }
    }

    /// Iterate over entries in the B-tree with the common filesystem key header parsed.
    pub fn iter_entries(
        &self,
    ) -> impl Iterator<Item = Result<(FileSystemKeyParsed, NodeValue)>> + '_ {
        self.inner
            .iter_entries(self.reader, self.object_map)
            .map(|res| {
                res.and_then(|(k, v)| {
                    Ok(FileSystemKeyParsed::from_bytes(k.into())?).and_then(|k| Ok((k, v)))
                })
            })
    }

    /// Iterate fully parsed file system records in this tree.
    pub fn iter_records(&self) -> impl Iterator<Item = Result<FileSystemRecord>> + '_ {
        self.inner
            .iter_entries(self.reader, self.object_map)
            .map(|res| {
                res.and_then(|(k, v)| {
                    Ok(FileSystemKeyParsed::from_bytes(k.into())?)
                        .and_then(|k| FileSystemRecord::new(k, v))
                })
            })
    }

    /// Iterate each distinct filesystem entry as a collection of its records.
    ///
    /// This iterates the tree and batches all records for the same filesystem
    /// ID together in a single entity.
    pub fn iter_collected_records(
        &self,
    ) -> impl Iterator<Item = Result<FilesystemRecordCollection>> + '_ {
        let mut current_records = vec![];
        let mut current_id = 0;

        self.iter_entries()
            .map(|x| Some(x))
            .chain(std::iter::once(None))
            .filter_map(move |entry| {
                match entry {
                    Some(Ok((k, v))) => {
                        let id = k.id();

                        if current_id == 0 {
                            current_id = id;
                        }

                        match FileSystemRecord::new(k, v) {
                            Ok(record) => {
                                // ID changed. Flush.
                                if id != current_id {
                                    let ret = FilesystemRecordCollection {
                                        records: Vec::from_iter(current_records.drain(..)),
                                    };

                                    current_records.clear();
                                    current_records.push(record);
                                    current_id = id;

                                    Some(Ok(ret))
                                } else {
                                    current_records.push(record);
                                    None
                                }
                            }
                            Err(err) => Some(Err(err)),
                        }
                    }
                    Some(Err(err)) => Some(Err(err)),
                    // Sentinel indicating end of entries.
                    None => {
                        if !current_records.is_empty() {
                            Some(Ok(FilesystemRecordCollection {
                                records: current_records.clone(),
                            }))
                        } else {
                            None
                        }
                    }
                }
            })
    }

    /// Obtain lightly parsed filesystem records for a given ID.
    ///
    /// Keys have their common filesystem header parsed. Values remain opaque.
    /// This makes this operation marginally slower than a B-tree lookup.
    pub fn records_for_id(
        &self,
        id: u64,
    ) -> impl Iterator<Item = Result<(FileSystemKeyParsed, NodeValue)>> + '_ {
        let cmp = move |key: &NodeKey| {
            let key = FileSystemKeyParsed::from_bytes(key.bytes())?;

            Ok(key.id().cmp(&id))
        };

        self.inner
            .find_entries_matching(self.reader, self.object_map, cmp)
            .map(|res| {
                res.and_then(|(k, v)| {
                    let k = FileSystemKeyParsed::from_bytes(k.into())
                        .expect("key casted above; this shouldn't fail");

                    Ok((k, v))
                })
            })
    }

    /// Resolve the collection of records for a given ID.
    pub fn collected_records_for_id(&self, id: u64) -> Result<FilesystemRecordCollection> {
        let records = self
            .records_for_id(id)
            .map(|res| res.and_then(|(k, v)| FileSystemRecord::new(k, v)))
            .collect::<Result<Vec<_>>>()?;

        Ok(FilesystemRecordCollection { records })
    }

    /// Obtain the collected records for the root inode (`/`).
    pub fn root_collected_records(&self) -> Result<FilesystemRecordCollection> {
        self.collected_records_for_id(INODE_ROOT_DIRECTORY)
    }

    /// Resolve the records for a given filesystem path.
    ///
    /// The input path must:
    ///
    /// * Be non-empty.
    /// * Be absolute.
    /// * Not have any parent directory (`..`) components.
    /// * Not have any prefix components.
    ///
    /// In other words, it should begin with `/` and name components must
    /// not be `..`. The `.` path component (e.g. `/etc/./password`) is allowed
    /// and effectively ignored.
    pub fn collected_records_for_path(&self, path: &Path) -> Result<FilesystemRecordCollection> {
        let mut components = path.components();

        let root = components.next().ok_or(ApfsError::PathEmpty)?;
        if !matches!(root, Component::RootDir) {
            return Err(ApfsError::PathNotAbsolute);
        }

        let mut record = self.root_collected_records()?;

        for component in components {
            match component {
                Component::CurDir => {}
                Component::Normal(p) => {
                    // TODO refine conversion semantics. Consider using Camino so
                    // caller is forced to reconcile encoding differences.
                    let name = p.to_string_lossy();

                    let (_, entry) = record
                        .directory_entries()
                        .find(|res| match res {
                            Ok((k, _)) => k.as_str() == name.as_ref(),
                            Err(_) => true,
                        })
                        .ok_or(ApfsError::PathNotFound)??;

                    record = self.collected_records_for_id(entry.file_id())?;
                }
                _ => {
                    return Err(ApfsError::PathInvalidComponent);
                }
            }
        }

        Ok(record)
    }

    /// Attempt to resolve the inode record for a filesystem identifier.
    pub fn get_inode(&self, id: u64) -> Result<Option<InodeRecord>> {
        let cmp = |key: &NodeKey| {
            let key = FileSystemKeyParsed::from_bytes(key.bytes())?;

            Ok((key.id(), key.object_type()).cmp(&(id, FileSystemObjectType::Inode)))
        };

        match self
            .inner
            .find_entries_matching(self.reader, self.object_map, cmp)
            .next()
        {
            Some(Ok((k, v))) => {
                let k = InodeRecordKeyParsed::from_bytes(k.into())?;
                let v = InodeRecordValueParsed::from_bytes(v.into())?;

                Ok(Some(InodeRecord { key: k, value: v }))
            }
            Some(Err(err)) => Err(err),
            None => Ok(None),
        }
    }

    /// Iterate over inode entries in the filesystem tree.
    ///
    /// This acts as a filtering map for the filesystem tree and emits inode
    /// entries casted to inode records.
    pub fn iter_inodes(&self) -> impl Iterator<Item = Result<InodeRecord>> + 'a {
        self.inner
            .iter_entries(self.reader, self.object_map)
            .filter_map(|res| match res {
                Ok((k, v)) => {
                    let k_data = k.bytes();

                    match FileSystemKeyParsed::from_bytes(k.into()) {
                        Ok(k) => match k.object_type() {
                            FileSystemObjectType::Inode => {
                                match (
                                    InodeRecordKeyParsed::from_bytes(k_data),
                                    InodeRecordValueParsed::from_bytes(v.into()),
                                ) {
                                    (Ok(k), Ok(v)) => Some(Ok(InodeRecord { key: k, value: v })),
                                    (Err(err), _) => Some(Err(err.into())),
                                    (_, Err(err)) => Some(Err(err.into())),
                                }
                            }
                            _ => None,
                        },
                        Err(err) => Some(Err(err.into())),
                    }
                }
                Err(err) => Some(Err(err)),
            })
    }

    /// Resolve the absolute path for an inode.
    pub fn inode_absolute_path(&self, record: &InodeRecord) -> Result<PathBuf> {
        if record.key.header().id() == INODE_ROOT_DIRECTORY {
            return Ok(PathBuf::from("/"));
        }

        let mut parts = vec![record.name()?.ok_or(ApfsError::InodeNoName)?];

        let mut parent_id = record.value.parent_id();

        while parent_id != INODE_ROOT_DIRECTORY && parent_id != INODE_ROOT_DIRECTORY_PARENT {
            let parent = self
                .get_inode(parent_id)?
                .ok_or(ApfsError::InodeMissingParent)?;

            parts.push(parent.name()?.ok_or(ApfsError::InodeNoName)?);
            parent_id = parent.value.parent_id();
        }

        parts.reverse();

        Ok(std::iter::once("/")
            .chain(parts.iter().map(|x| x.as_str()))
            .collect())
    }

    /// Obtain the relative path of an inode.
    pub fn inode_relative_path(&self, record: &InodeRecord) -> Result<PathBuf> {
        Ok(PathBuf::from_iter(
            self.inode_absolute_path(record)?.components().skip(1),
        ))
    }
}
