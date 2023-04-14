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
    create_path_for_file(file_path)?;
    std::fs::File::create(file_path)
        .with_context(|| format!("Cannot create file {}", file_path.display()))
}

/// Create path for file, but don't create the file.
pub fn create_path_for_file(file_path: &Path) -> Result<()> {
    let dir = file_path
        .parent()
        .ok_or_else(|| anyhow!("Error determining parent of {}", file_path.display()))?;

    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "Cannot create dir {} for file {}",
            dir.to_string_lossy(),
            file_path.display()
        )
    })
}

/// Tries to rename the relative file under the source dir to the target dir.
/// Renaming will fail if those dirs are on different mount points. In that
/// case we try to copy and delete instead.
pub fn move_file(source_base_dir: &Path, target_base_dir: &Path, relative: &str) -> Result<()> {
    let original_file = source_base_dir.join(relative);
    let target_file = target_base_dir.join(relative);

    create_path_for_file(&target_file)?;

    if !original_file.exists() {
        return Err(anyhow!(
            "Source file {} does not exist",
            original_file.to_string_lossy()
        ));
    }

    if std::fs::rename(&original_file, &target_file).is_err() {
        // Move failed. Try to copy and delete instead.
        std::fs::copy(&original_file, &target_file).with_context(|| {
            format!(
                "Cannot copy file from {} to {}",
                original_file.to_string_lossy(),
                target_file.to_string_lossy()
            )
        })?;

        std::fs::remove_file(&original_file).with_context(|| {
            format!(
                "Cannot delete file from {}",
                original_file.to_string_lossy(),
            )
        })?;
    }

    Ok(())
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
