use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};

use filetime::{set_file_mtime, FileTime};
use log::{info, warn};
use rpki::{
    repository::{sigobj::SignedObject, Cert, Crl, Manifest, Roa},
    rrdp::ProcessSnapshot,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::{self, Config},
    file_ops,
    rrdp::RrdpState,
    util::{self, Time},
};

pub fn update_from_rrdp_state(
    rrdp_state: &RrdpState,
    changed: bool,
    config: &Config,
) -> Result<()> {
    // Check that there is a current snapshot, if not, there is no work
    if rrdp_state.snapshot_path().is_none() {
        return Ok(());
    }

    // We can assume now that there is a snapshot and unwrap things for it
    let snapshot_path = rrdp_state.snapshot_path().unwrap();
    let snapshot = rrdp_state.snapshot().unwrap();
    let session_id = snapshot.session_id();
    let serial = snapshot.serial();

    let mut rsync_state = RsyncDirState::recover(config)?;

    let new_revision = RsyncRevision { session_id, serial };

    if changed {
        let mut writer = RsyncFromSnapshotWriter {
            out_path: new_revision.path(config),
            include_host_and_module: config.rsync_include_host,
        };
        writer.create_out_path_if_missing()?;
        writer.from_snapshot_path(&snapshot_path)?;

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
                "Renaming the rsync directory for previous revision to: {:?}",
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

struct RsyncFromSnapshotWriter {
    out_path: PathBuf,
    include_host_and_module: bool,
}

impl RsyncFromSnapshotWriter {

    /// Creates an empty directory for the rsync out_path. Particularly needed if the snapshot
    /// is empty since no files (and parent dirs) would be created in that case - and we want to
    /// see an empty directory. See issue #62.
    fn create_out_path_if_missing(&self) -> Result<()> {
        if !self.out_path.exists() {
            std::fs::create_dir_all(&self.out_path)
                .with_context(|| format!("Cannot create output directory for rsync at {:?}", &self.out_path))
        } else {
            Ok(())
        }
    }

    /// Processes the given snapshot and writes any published files under the
    /// rsync out_path directory
    fn from_snapshot_path(&mut self, snapshot: &Path) -> Result<()> {
        let source_file = File::open(snapshot)?;
        let buf_reader = BufReader::new(source_file);
        self.process(buf_reader)?;
        Ok(())
    }
}

impl ProcessSnapshot for RsyncFromSnapshotWriter {
    type Err = anyhow::Error;

    fn meta(&mut self, _session_id: Uuid, _serial: u64) -> Result<()> {
        Ok(()) // nothing to do
    }

    fn publish(
        &mut self,
        uri: rpki::uri::Rsync,
        data: &mut rpki::rrdp::ObjectReader,
    ) -> Result<()> {
        let path = if self.include_host_and_module {
            self.out_path.join(format!(
                "{}/{}/{}",
                uri.authority(),
                uri.module_name(),
                uri.path()
            ))
        } else {
            self.out_path.join(uri.path())
        };

        // Read the bytes into memory, we will need to parse this in order
        // to fix the mtime of the file. In other words.. we _could_ copy
        // the bytes from the reader into a file on disk, but then we would
        // have to re-read them to parse them anyway.
        let mut bytes: Vec<u8> = vec![];
        data.read_to_end(&mut bytes)?;

        file_ops::write_buf(&path, &bytes).with_context(|| {
            format!(
                "Could not copy element for uri: {}, to path: {}",
                uri,
                path.to_string_lossy()
            )
        })?;

        if let Err(e) = fix_since(&path, &bytes) {
            warn!("{}", e);
        }

        Ok(())
    }
}

// Try to fix the modification time for a repository object.
// This is needed because otherwise some clients will always think
// there is an update.
fn fix_since(path: &Path, data: &[u8]) -> Result<()> {
    let path_str = path.to_string_lossy();
    let time = if path_str.ends_with(".cer") {
        Cert::decode(data).map(|cert| cert.validity().not_before())
    } else if path_str.ends_with(".crl") {
        Crl::decode(data).map(|crl| crl.this_update())
    } else if path_str.ends_with(".mft") {
        Manifest::decode(data, false).map(|mft| mft.this_update())
    } else if path_str.ends_with(".roa") {
        Roa::decode(data, false).map(|roa| roa.cert().validity().not_before())
    } else {
        // Try to parse this as a generic RPKI signed object
        SignedObject::decode(data, false).map(|signed| signed.cert().validity().not_before())
    }
    .map_err(|_| anyhow!("Cannot parse object at: {} to derive mtime", path_str))?;

    let mtime = FileTime::from_unix_time(time.timestamp(), 0);
    set_file_mtime(&path, mtime).map_err(|e| {
        anyhow!(
            "Cannot modify mtime for object at: {}, error: {}",
            path_str,
            e
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use filetime::FileTime;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::util::test_with_dir;

    use super::RsyncFromSnapshotWriter;

    #[test]
    fn write_rsync_from_snapshot() {
        test_with_dir("write_rsync_from_snapshot", |dir| {
            let snapshot_path = PathBuf::from("./test-resources/rrdp-rev2658/e9be21e7-c537-4564-b742-64700978c6b4/2658/rnd-sn/snapshot.xml");

            let out_path = dir.join("rsync");
            let include_host_and_module = false;

            let mut writer = RsyncFromSnapshotWriter {
                out_path,
                include_host_and_module,
            };
            writer.from_snapshot_path(&snapshot_path).unwrap();

            fn check_mtime(dir: &Path, path: &str, timestamp: i64) {
                let path = dir.join(path);
                let metadata = fs::metadata(path).unwrap();
                let mtime = FileTime::from_last_modification_time(&metadata);
                assert_eq!(timestamp, mtime.unix_seconds())
            }

            check_mtime(
                &dir,
                "rsync/ta/0/3490C0DEEA1F2E5605230550130F12D42FDE1FCD.cer",
                1600268228,
            );

            check_mtime(
                &dir,
                "rsync/Acme-Corp-Intl/3/A4E953A4133AC82A46AE19C2E7CC635B51CD11D3.mft",
                1622637098,
            );

            check_mtime(
                &dir,
                "rsync/Acme-Corp-Intl/5/D2E73D77B71B22FAAB38F5A62DF488283FE97932.crl",
                1622621702,
            );

            check_mtime(&dir, "rsync/Acme-Corp-Intl/3/AS40224.roa", 1620657233);
        });
    }
}
