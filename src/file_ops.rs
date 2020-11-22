use crate::config;

use anyhow::{anyhow, Result};

use std::fs::File;
use std::io::prelude::*; // for File::write_all()
use std::path::{Path, PathBuf};

pub fn write_buf(file_path: &Path, buf: &[u8]) -> Result<()> {
    let dir = &file_path.parent().ok_or_else(|| anyhow!("Error determining parent of {:?}", &file_path))?;
    std::fs::create_dir_all(&dir)?;
    std::fs::File::create(file_path)?.write_all(buf)?;
    Ok(())
}

pub fn read_file(file_path: &Path) -> Result<Vec<u8>> {
    debug!("Loading file {:?}", &file_path);
    let mut f = File::open(file_path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn set_path_ext(path: &Path, ext: &str) -> PathBuf {
    let mut res = path.to_path_buf();
    res.set_extension(ext);
    res
}

// Assumes that the old data is named XXX and the new data is named XXX.tmp.
fn install_using_moves(
    final_path: &Path,
    is_dir: bool,
    keep_with_extension: Option<String>) -> Result<()>
{
    // This path represents the new data
    let new_path = set_path_ext(final_path, config::TMP_FILE_EXT);

    let delete_after = keep_with_extension.is_none();

    // This path is where the current (old) data will be moved out of the way to
    let old_extension = keep_with_extension.unwrap_or(config::OLD_FILE_EXT.to_string());
    // Don't lose the original extension, append a new one
    let old_path_str = format!("{}.{}", final_path.to_str().unwrap(), old_extension);
    let old_path = Path::new(&old_path_str);

    if !final_path.exists() {
        trace!("Atomic move {:?} -> {:?}", &new_path, &final_path);
    } else {
        trace!("Atomic move {:?} -> {:?} -> {:?}", &new_path, &final_path, &old_path);
    }

    // The destination for the current data that will be moved out of the way to
    // the "old" location should be free.
    if (is_dir && old_path.is_dir()) || (!is_dir && old_path.is_file()) {
        panic!("Unable to perform atomic move, old data in the way: {:?}", &old_path);
    }

    // Move old data out of the way
    if (is_dir && final_path.is_dir()) || (!is_dir && final_path.is_file()) {
        std::fs::rename(&final_path, &old_path)?;
    }

    // Move new data to final home
    std::fs::rename(&new_path, &final_path)?;

    if delete_after {
        // Remove old data, if any
        if is_dir {
            if old_path.is_dir() {
                std::fs::remove_dir_all(&old_path)?;
            }
        } else if old_path.is_file() {
            std::fs::remove_file(&old_path)?;
        }
    }

    Ok(())
}

pub fn install_new_dir(final_path: &Path, keep_with_extension: String) -> Result<()> {
    install_using_moves(final_path, true, Some(keep_with_extension))
}

pub fn install_new_file(final_path: &Path, keep_with_extension: String) -> Result<()> {
    install_using_moves(final_path, false, Some(keep_with_extension))
}