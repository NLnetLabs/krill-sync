use std::{
    fs::File,
    io::prelude::*, // for File::write_all()
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use log::trace;

pub fn write_buf(file_path: &Path, buf: &[u8]) -> Result<()> {
    create_file(file_path)?
        .write_all(buf)
        .with_context(|| format!("Cannot write file {}", file_path.display()))?;

    Ok(())
}

/// Create an empty file for a path
pub fn create_file(file_path: &Path) -> Result<std::fs::File> {
    let dir = file_path
        .parent()
        .ok_or_else(|| anyhow!("Error determining parent of {}", file_path.display()))?;

    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "Cannot create dir {} for file {}",
            dir.to_string_lossy(),
            file_path.display()
        )
    })?;

    std::fs::File::create(file_path)
        .with_context(|| format!("Cannot create file {}", file_path.display()))
}

pub fn remove_file_and_empty_parent_dirs(path: &Path) -> Result<()> {
    if path.is_file() {
        std::fs::remove_file(path)
            .with_context(|| format!("Cannot remove file {}", path.display()))?;
    } else if path.is_dir() {
        std::fs::remove_dir(path)
            .with_context(|| format!("Cannot remove dir {}", path.display()))?;
    }

    // Recurse to do a 'best effort' removal of the parent if it exists. This
    // will fail in case it's a non empty directory. That is fine and expected,
    // it means that we are done.
    if let Some(parent) = path.parent() {
        let _ = remove_file_and_empty_parent_dirs(parent);
    }

    Ok(())
}

pub fn read_file(file_path: &Path) -> Result<Bytes> {
    trace!("Loading file {}", file_path.display());
    let mut f = File::open(file_path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(Bytes::from(buf))
}

pub fn path_with_extension(path: &Path, ext: &str) -> PathBuf {
    let mut res = path.to_path_buf();
    res.set_extension(ext);
    res
}
