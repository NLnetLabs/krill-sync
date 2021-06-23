use std::{
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use filetime::{FileTime, set_file_mtime};
use log::{info, trace};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::{self, Config},
    file_ops,
    rrdp::{CurrentObject, RrdpState},
    util::{self, Time},
};

pub fn update_from_rrdp_state(
    rrdp_state: &RrdpState,
    changed: bool,
    config: &Config,
) -> Result<()> {
    let mut rsync_state = RsyncDirState::recover(config)?;

    let new_revision = RsyncRevision {
        session_id: rrdp_state.session_id(),
        serial: rrdp_state.serial(),
    };

    if changed {
        write_rsync_content(&new_revision.path(config), config.rsync_multiple_auth, rrdp_state.elements())?;

        if config.rsync_dir_use_symlinks() {
            symlink_current_to_new_revision_dir(&new_revision, config)?;
        } else {
            rename_new_revision_dir_to_current(&new_revision, &rsync_state, config)?;
        }

        rsync_state.update_current(new_revision);
    }

    rsync_state.clean_old(config)?;
    rsync_state.persist(config)?;

    Ok(())
}

/// Create a new symlink then rename it. We need to do this because the std library
/// refuses to overwrite an existing symlink. And if we were to remove it first, then
/// we would introduce a race condition for clients accessing.
fn symlink_current_to_new_revision_dir(
    new_revision: &RsyncRevision,
    config: &Config,
) -> Result<()> {
    info!(
        "Updating symlink 'current' to '{}' under rsync dir '{:?}'",
        new_revision.dir_name(),
        config.rsync_dir
    );
    let current_path = config.rsync_dir_current();

    let tmp_name = file_ops::path_with_extension(&current_path, config::TMP_FILE_EXT);
    if tmp_name.exists() {
        std::fs::remove_file(&tmp_name).with_context(|| {
            format!(
                "Could not remove lingering temporary symlink for current rsync dir at '{:?}'",
                tmp_name
            )
        })?;
    }

    std::os::unix::fs::symlink(new_revision.dir_name(), &tmp_name).with_context(|| {
        format!(
            "Could not create temporary symlink for new rsync content at '{:?}'",
            tmp_name
        )
    })?;

    std::fs::rename(&tmp_name, &current_path).with_context(|| {
        format!(
            "Could not rename symlink for current rsync dir from '{:?}' to '{:?}'",
            tmp_name, current_path
        )
    })?;

    Ok(())
}

/// Rename the path for the new revision to the current rsync path, *after*
/// renaming any existing current path to the serial and session for that
/// revision.
fn rename_new_revision_dir_to_current(
    new_revision: &RsyncRevision,
    rsync_state: &RsyncDirState,
    config: &Config,
) -> Result<()> {
    info!("Renaming rsync folders for close to atomic update of the rsync module dir");

    let current_path = config.rsync_dir_current();

    if let Some(current) = &rsync_state.current {
        let current_preserve_path = current.path(config);

        if current_path.exists() {
            info!(
                "Backing up rsync directory for previous revision to: {:?}",
                current_preserve_path
            );
            std::fs::rename(&current_path, &current_preserve_path).with_context(|| {
                format!(
                    "Could not rename current rsync dir from '{:?}' to '{:?}'",
                    current_path, current_preserve_path
                )
            })?;
        }
    }

    info!("Rename rsync dir for new revision to '{:?}'", current_path);
    std::fs::rename(&new_revision.path(config), &current_path).with_context(|| {
        format!(
            "Could not rename new rsync dir from '{:?}' to '{:?}'",
            new_revision.path(config),
            current_path
        )
    })?;

    Ok(())
}

fn write_rsync_content<'a>(
    out_path: &Path,
    include_host_and_module: bool,
    elements: impl Iterator<Item = &'a CurrentObject>,
) -> Result<()> {
    info!("Writing rsync repository to: {:?}", out_path);
    for element in elements {
        let path = if include_host_and_module {
            let uri = element.uri();
            out_path.join(format!("{}/{}/{}", uri.authority(), uri.module_name(), uri.path()))
        } else {
            out_path.join(element.uri().path())
        };

        trace!("Writing rsync file {:?}", &path);
        file_ops::write_buf(&path, element.data())?;

        let mtime = FileTime::from_unix_time(element.since().timestamp(), 0);
        set_file_mtime(&path, mtime)?;
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RsyncDirState {
    current: Option<RsyncRevision>,
    old: Vec<DeprecatedRsyncRevision>,
}

impl RsyncDirState {
    /// Gets the current state from disk, if a state file exists. Otherwise returns
    /// a new blank state.
    fn recover(config: &Config) -> Result<Self> {
        let state_path = config.rsync_state_path();
        if state_path.exists() {
            let json_bytes = file_ops::read_file(&state_path)
                .with_context(|| format!("Cannot read rsync state file at: {:?}", state_path))?;
            serde_json::from_slice(json_bytes.as_ref()).with_context(|| {
                format!(
                    "Cannot deserialize json for current state from {:?}",
                    state_path
                )
            })
        } else {
            Ok(RsyncDirState {
                current: None,
                old: vec![],
            })
        }
    }

    /// Persists the state to disk
    fn persist(&self, config: &Config) -> Result<()> {
        let state_path = config.rsync_state_path();
        let json = serde_json::to_string_pretty(&self)?;
        file_ops::write_buf(&state_path, json.as_bytes()).with_context(|| "Could not save state.")
    }

    /// Updates the current revision for this state, moves a possible
    /// existing current state to old.
    fn update_current(&mut self, current: RsyncRevision) {
        let existing = std::mem::replace(&mut self.current, Some(current));
        if let Some(existing) = existing {
            self.old.push(existing.deprecate());
        }
    }

    /// Cleans old directories from disk when their time has come, and updates
    /// this state (forgets these old versions). Will throw an error if removing
    /// an old dir fails, but will simply skip removing old dirs if they had
    /// already been removed.
    fn clean_old(&mut self, config: &Config) -> Result<()> {
        let clean_before = Time::seconds_ago(config.cleanup_after);

        for old in self
            .old
            .iter()
            .filter(|deprecated| deprecated.since <= clean_before)
        {
            let path = old.revision.path(config);
            if path.exists() {
                info!(
                    "Removing rsync directory: {:?}, deprecated since: {}",
                    path, old.since
                );
                // Try to remove the old directory if it still exists
                std::fs::remove_dir_all(&path).with_context(|| {
                    format!("Could not remove rsync dir for old revision at: {:?}", path)
                })?;
            }
        }

        self.old
            .retain(|deprecated| deprecated.since > clean_before);

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]

struct RsyncRevision {
    #[serde(deserialize_with = "util::de_uuid", serialize_with = "util::ser_uuid")]
    session_id: Uuid,
    serial: u64,
}

impl RsyncRevision {
    fn dir_name(&self) -> String {
        format!("session_{}_serial_{}", self.session_id, self.serial)
    }

    fn path(&self, config: &Config) -> PathBuf {
        config.rsync_dir.join(&self.dir_name())
    }

    fn deprecate(self) -> DeprecatedRsyncRevision {
        DeprecatedRsyncRevision {
            since: Time::now(),
            revision: self,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DeprecatedRsyncRevision {
    since: Time,
    revision: RsyncRevision,
}
