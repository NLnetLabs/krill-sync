use crate::file_ops::write_buf;

use anyhow::{anyhow, Result};

use std::path::Path;

pub fn lock(pid_file: &Path) -> Result<()> {
    if pid_file.is_file() {
        return Err(anyhow!("Lock file {:?} exists, aborting", &pid_file));
    }
    write_buf(&pid_file, &format!("{}\n", std::process::id()).as_bytes().to_vec())?;
    Ok(())
}

pub fn unlock(pid_file: &Path) -> Result<()> {
    if pid_file.is_file() {
        std::fs::remove_file(pid_file)?;
    }

    Ok(())
}