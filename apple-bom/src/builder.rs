// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {
    crate::{BomPath, BomPathType, Error},
    chrono::{DateTime, Utc},
    simple_file_manifest::{S_IFDIR, S_IRGRP, S_IROTH, S_IRUSR, S_IWUSR, S_IXGRP, S_IXUSR},
    std::{collections::BTreeMap, io::Read, path::Path},
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
}
