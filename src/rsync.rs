use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;

use rpki::rrdp::PublishElement;
use rpki::{
    rrdp::Snapshot,
    uri,
};

use crate::config::{self, Config};
use crate::file_ops;
use crate::rrdp::RrdpState;

fn make_rsync_repo_path(uri: &uri::Rsync) -> PathBuf {
    // Drop the module as the proper module name is determined by and part of
    // the rsyncd configuration and thus the user invoking krill-sync should
    // ensure that they direct krill-sync to write the rsync files out to the
    // directory that matches the location expected by rsyncd.
    PathBuf::from_str(uri.path()).unwrap() // cannot fail (Infallible)
}

pub fn build_repo_from_rrdp_snapshot(
    rrdp_state: &RrdpState,
    config: &Config,
) -> Result<()> {
    let rsync_dir = &config.rsync_dir;
    
    let session_id = rrdp_state.session_id();
    let serial = rrdp_state.serial();

    let rsync_dir_for_snapshot_name = format!("revision_{}_{}", session_id, serial);
    
    let out_path = rsync_dir.join(&rsync_dir_for_snapshot_name);
    let current_path = rsync_dir.join("current");

    info!("Writing rsync repository to: {:?}", out_path);

    write_rsync_content(&out_path, rrdp_state.elements())?;

    if config.rsync_dir_use_symlinks() {
        info!("Updating symlink 'current' to '{}' under rsync dir '{:?}'", rsync_dir_for_snapshot_name, rsync_dir);
        // Create a new symlink then rename it. We need to do this because the std library
        // refuses to overwrite an existing symlink. And if we were to remove it first, then
        // we would introduce a race condition for clients accessing.

        let tmp_name = file_ops::path_with_extension(&current_path, config::TMP_FILE_EXT);
        if tmp_name.exists() {
            std::fs::remove_file(&tmp_name)
                .with_context(|| {
                    format!("Could not remove lingering temporary symlink for current rsync dir at '{:?}'", tmp_name)})?;
        }

        std::os::unix::fs::symlink(rsync_dir_for_snapshot_name, &tmp_name)
            .with_context(|| 
                format!("Could not create temporary symlink for new rsync content at '{:?}'", tmp_name))?;

        std::fs::rename(&tmp_name, &current_path)
            .with_context(|| {
                format!("Could not rename symlink for current rsync dir from '{:?}' to '{:?}'", tmp_name, current_path)})?;
    } else {
        info!("Renaming rsync folders for close to atomic update of the rsync module dir");

        // preserve current revision name in file, so we can use it for later renames
        let current_revision_id_file = rsync_dir.join("current-revision-info.txt");

        if current_path.exists() {
            // Try to rename the current directory before renaming the newly written directory to this.

            if let Ok(prev_rev_id_bytes) = file_ops::read_file(&current_revision_id_file) {
                // There seems to be a previous revision, so try to parse it and rename the current
                // rsync directory to this.
                if let Ok(prev_rev_id_str) = std::str::from_utf8(&prev_rev_id_bytes) {
                    
                    let prev_rev_id_path = PathBuf::from(prev_rev_id_str);
                    info!("Rename current rsync dir from '{:?}' to '{:?}'", current_path, prev_rev_id_path);
                    std::fs::rename(&current_path, &prev_rev_id_path)
                        .with_context(|| {
                            format!(
                                "Could not rename current rsync dir from '{:?}' to '{:?}'",
                                current_path,
                                prev_rev_id_path)})?;
    
                } else {
                    warn!("Could not parse previous revision for rsync directory");
                }    
            }
        }

        info!("Preserving revision path for future reference in '{:?}'", current_revision_id_file);
        file_ops::write_buf(&current_revision_id_file, out_path.to_string_lossy().as_bytes())
            .with_context(|| 
                format!("Could not write current revision info id file '{:?}'", current_revision_id_file))?;
        
        
        info!("Rename new rsync dir from '{:?}' to '{:?}'", out_path, current_path);
        std::fs::rename(&out_path, &current_path)
            .with_context(||
                format!("Could not rename new rsync dir from '{:?}' to '{:?}'", out_path, current_path))?;
    }

    Ok(())
}

fn write_rsync_content(
    out_path: &Path,
    elements: &[PublishElement],
) -> Result<()> {
    for element in elements {
        let path = out_path.join(make_rsync_repo_path(element.uri()));
        trace!("Writing rsync file {:?}", &path);
        file_ops::write_buf(&path, element.data())?;
    }
    
    Ok(())
}
