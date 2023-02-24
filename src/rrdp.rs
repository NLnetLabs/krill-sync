use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use rpki::{
    rrdp::{self, DeltaInfo, Hash, NotificationFile, SnapshotInfo},
    uri::Https,
};

use crate::{
    config::Config,
    fetch::{FetchMap, FetchMode, FetchSource, Fetcher, NotificationFileResponse},
    file_ops,
    util::{self, Time},
    validation::{LocalNotificationFile, Tal, Validator},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct RrdpState {
    /// The notification source information
    notification_source: NotificationSource,

    /// Maps notification, and other URIs to disk and vice versa
    mappings: SourceMappings,

    /// Current snapshot state (xml, hash, path)
    snapshot: Option<SnapshotState>,

    /// Delta states (xml, hash, path)
    deltas: VecDeque<DeltaState>,

    /// Deprecated files - which may be cleaned up after some time
    deprecated_files: Vec<DeprecatedFile>,

    /// Embedded validator
    #[serde(skip_serializing_if = "Option::is_none")]
    validator: Option<Validator>,
}

impl RrdpState {
    /// Create a new, empty, RrdpState which can then be updated.
    pub fn create(config: &Config) -> Result<Self> {
        info!("No prior state found, will build up state from latest snapshot at source");

        let notification_uri = &config.notification_uri;
        let rrdp_dir = &config.rrdp_dir;

        let notification_source = NotificationSource::build(notification_uri.clone())?;
        let mappings = SourceMappings::build(notification_uri.clone(), rrdp_dir.clone())?;

        Ok(RrdpState {
            notification_source,
            mappings,
            snapshot: None,
            deltas: VecDeque::new(),
            deprecated_files: vec![],
            validator: None,
        })
    }

    /// Recover from disk. Reads the last known state from disk and re-parses the current snapshot
    /// and all delta files. Returns an error if any of this fails.
    pub fn recover(state_path: &Path) -> Result<Self> {
        debug!("Recovering prior state");
        let json_bytes = file_ops::read_file(state_path)
            .with_context(|| format!("Cannot read state file at: {}", state_path.display()))?;

        // Recover state with meta info from disk.
        let recovered: RrdpState =
            serde_json::from_slice(json_bytes.as_ref()).with_context(|| {
                format!(
                    "Cannot deserialize json for current state from {}",
                    state_path.display()
                )
            })?;

        if let Some(snapshot) = &recovered.snapshot {
            info!(
                "Recovered prior state => session: {}, serial: {}",
                snapshot.session_id, snapshot.serial
            );
        }

        Ok(recovered)
    }

    /// Try to update this state using the notification file found in the specified fetcher.
    ///
    /// Returns:
    ///   Ok(true)  if there was an update
    ///   Ok(false) if there was no update (serial and session match current)
    ///   Err       if there was an error trying to update
    pub fn update(&mut self, limit: Option<usize>, fetcher: &Fetcher) -> Result<bool> {
        match self.notification_source.fetch(fetcher)? {
            None => {
                debug!("Notification file at source to sync was not changed, no updated needed.");
                Ok(false)
            }
            Some(mut notification) => {
                if !notification.sort_and_verify_deltas(limit) {
                    return Err(anyhow!("Notification file contained gaps in deltas"));
                }

                let delta_cut_off = if let Some(snapshot) = &self.snapshot {
                    if snapshot.session_id() != notification.session_id() {
                        // session reset:
                        //  - set delta cut off so that all deltas will be deprecated
                        snapshot.serial() + 1
                    } else {
                        match snapshot.serial().cmp(&notification.serial()) {
                            std::cmp::Ordering::Less => {
                                // session unchanged, and there is an update:
                                // - set delta cut off to deltas no longer in notification
                                notification
                                    .deltas()
                                    .first() // deltas are ordered from low to high
                                    .map(|d| d.serial())
                                    .unwrap_or_else(|| notification.serial())
                            }
                            std::cmp::Ordering::Equal => {
                                // no change, session and serial unchanged
                                debug!("Notification file unchanged (etag not supported?), no update needed.");
                                return Ok(false);
                            }
                            std::cmp::Ordering::Greater => {
                                // This is a problem..
                                return Err(anyhow!(format!(
                                    "The notification file serial '{}' is *before* our serial '{}'. Server session reset recommended.",
                                    notification.serial(),
                                    snapshot.serial()
                                )));
                            }
                        }
                    }
                } else {
                    // There is no current snapshot, presumably there will be no details
                    // either. Still set the cut off to deprecate any current delta so
                    // that we don't need different logic below. This, and deprecating
                    // the non-existing snapshot, will be a no-op.
                    notification.serial()
                };

                self.snapshot_update(&notification, fetcher)?;
                self.deltas_update(&notification, fetcher, delta_cut_off, limit)?;

                Ok(true)
            }
        }
    }

    /// Pre-validate the new RRDP state.
    ///
    /// Dependent on configuration
    pub fn pre_validate(&mut self, config: &Config) -> Result<()> {
        self.reconfigure_validator(config)?;

        if let Some(validator) = self.validator.as_ref() {
            info!("Validate using configured TALs and report on source repository");
            let candidate_notification = self.make_notification_file()?;
            let local = LocalNotificationFile {
                uri: config.notification_uri.clone(),
                notification: candidate_notification,
            };

            let report = validator.validate(Some(&local))?;

            if let Some(rrdp_report) = report.rrdp_repositories.get(&config.notification_uri) {
                let summary = format!(
                    "{}: {} issues, {} certs, {} roas, {} vrps, {} aspas, {} router certs",
                    config.notification_uri,
                    rrdp_report.issues.len(),
                    rrdp_report.nr_ca_certs,
                    rrdp_report.nr_roas,
                    rrdp_report.nr_vrps,
                    rrdp_report.nr_aspas,
                    rrdp_report.nr_router_certs
                );
                if rrdp_report.issues.is_empty() {
                    info!("{summary}");
                    Ok(())
                } else {
                    let mut issues = vec![];
                    for issue in &rrdp_report.issues {
                        if let Some(uri) = &issue.uri {
                            issues.push(format!("{} : {}", uri, issue.msg));
                        } else {
                            issues.push(issue.msg.clone());
                        }
                    }

                    if config.tal_reject_invalid {
                        error!("{summary}");
                        for issue in issues {
                            error!("   {issue}");
                        }
                        Err(anyhow!("Aborting sync because of validation issues"))
                    } else {
                        warn!("{summary}");
                        for issue in issues {
                            warn!("   {issue}");
                        }
                        Ok(())
                    }
                }
            } else if config.tal_reject_invalid {
                Err(anyhow!(
                    "The repository {} was not seen in validation. Exiting",
                    config.notification_uri
                ))
            } else {
                warn!(
                    "The repository {} was not seen in validation.",
                    config.notification_uri
                );
                Ok(())
            }
        } else {
            trace!("Skipping validation, no TALs were configured.");
            Ok(())
        }
    }

    /// Set up a new validator based on configuration.
    ///
    /// If there are no configured TAL files then this ensures that we
    /// have no Validator - even if a previous run - with different
    /// configuration settings had one.
    ///
    /// If there are configured TAL files, then we *always* revalidate
    /// the TA certificates. And then we check whether a possible
    /// pre-existing Validator for this state can be re-used. Re-using
    /// an existing Validator has the benefit that we can use cached
    /// repository data, and reduce the load and dependency on third
    /// party repositories in the RPKI tree.
    ///
    /// But, we only do this in case there were no changes in the TALs,
    /// or the configuration of our own RRDP notify XML and RRDP data
    /// path. Although it might be possible to handle certain changes,
    /// this can get fairly complicated - so in that case we just start
    /// with a clean new Validator without existing state instead.
    fn reconfigure_validator(&mut self, config: &Config) -> Result<()> {
        if config.tal_files.is_empty() {
            self.validator = None;
        } else {
            let validator = Self::create_validator(config)?;
            if self.new_validator_needed(&validator) {
                debug!("Using new validator instance.");
                self.validator = Some(validator);
            } else {
                debug!("Re-using existing validator instance.")
            }
        }
        Ok(())
    }

    /// Creates a new Validator instance after validating the
    /// configured TALs.
    ///
    /// Note that theoretically a Validator can be created with
    /// an empty TAL list. It just would not have any work to do.
    /// In practice we don't create such a validator, but leave
    /// the validator option in `RrdpState` as None in that case
    /// because this is more explicit, and it lets us clear out
    /// unnecessary data in the state.
    fn create_validator(config: &Config) -> Result<Validator> {
        let mut tals = vec![];
        for tal_file in &config.tal_files {
            let tal_bytes = file_ops::read_file(tal_file)?;
            let tal_name = tal_file.to_string_lossy().to_string();
            let tal = Tal::parse(tal_name, tal_bytes, None)?;
            tals.push(tal);
        }

        let notification_uri = config.notification_uri.clone();

        let base_https = notification_uri
            .parent()
            .ok_or(anyhow!("cannot get parent dir of notification_uri"))?;

        let fetch_map = FetchMap::new(base_https, FetchSource::File(config.rrdp_dir.clone()));
        let fetcher = Fetcher::new(notification_uri, Some(fetch_map), FetchMode::Insecure);

        Ok(Validator::new(tals, vec![fetcher]))
    }

    /// Return false if we have an existing Validator that can be used.
    fn new_validator_needed(&self, new_validator: &Validator) -> bool {
        self.validator
            .as_ref()
            .map(|existing| !existing.equivalent(new_validator))
            .unwrap_or(true)
    }

    /// Cleans deprecated files and their parent directories if they are empty
    pub fn clean(&mut self, config: &Config) -> Result<()> {
        let clean_before = Time::seconds_ago(config.cleanup_after);

        for deprecated in self
            .deprecated_files
            .iter()
            .filter(|d| d.since <= clean_before)
        {
            let path = &deprecated.path;
            if path.exists() {
                info!(
                    "Removing RRDP file: {}, deprecated since: {}",
                    path.display(),
                    deprecated.since
                );
                file_ops::remove_file_and_empty_parent_dirs(path)?;
            }
        }

        self.deprecated_files.retain(|d| d.since > clean_before);

        Ok(())
    }

    /// Persist the RRDP state to disk (as json)
    pub fn persist(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self)?;

        file_ops::write_buf(path, json.as_bytes())
            .with_context(|| format!("Could not save state to {}.", path.display()))
    }

    /// Writes the notification file to disk. Will first write to a
    /// temporary file and then rename it to avoid serving partially
    /// written files.
    pub fn write_notification(&self) -> Result<()> {
        let notification_file_filename_final = self.notification_source.name();
        let notification_file_filename_tmp = self.notification_source.tmp_name();

        let path_final = self.mappings.path(notification_file_filename_final);
        let path_tmp = self.mappings.path(&notification_file_filename_tmp);

        info!("Updating notification file at {}", path_final.display());

        let notification = self.make_notification_file()?;

        let mut bytes: Vec<u8> = vec![];
        notification.write_xml(&mut bytes)?;

        file_ops::write_buf(&path_tmp, &bytes).with_context(|| {
            format!(
                "Could not write temporary notification file to: {}",
                path_tmp.display()
            )
        })?;

        fs::rename(&path_tmp, &path_final).with_context(|| {
            format!(
                "Could not rename {} to {}",
                path_tmp.display(),
                path_final.display()
            )
        })?;

        Ok(())
    }

    fn make_notification_file(&self) -> Result<NotificationFile> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| anyhow!("Trying to write notification file without snapshot"))?;

        let snapshot_uri = self.mappings.uri(snapshot.rel_path())?;
        let snapshot_hash = snapshot.hash();

        let snapshot_info = SnapshotInfo::new(snapshot_uri, snapshot_hash);

        let mut deltas = vec![];
        for delta in &self.deltas {
            let serial = delta.serial();
            let hash = delta.hash();
            let uri = self.mappings.uri(delta.rel_path())?;

            deltas.push(DeltaInfo::new(serial, uri, hash));
        }

        Ok(NotificationFile::new(
            snapshot.session_id(),
            snapshot.serial(),
            snapshot_info,
            deltas,
        ))
    }

    /// Update the snapshot, downloads it and checks the hash,
    /// and deprecates the old snapshot if it exists.
    fn snapshot_update(
        &mut self,
        notification: &NotificationFile,
        fetcher: &Fetcher,
    ) -> Result<()> {
        // deprecate old snapshot if it is present
        if let Some(old_path) = self.snapshot_path() {
            self.deprecated_files.push(DeprecatedFile::new(old_path));
        }

        let snapshot_info = notification.snapshot();
        let target = self.mappings.path_for_uri(snapshot_info.uri())?;
        fetcher.retrieve_file(snapshot_info.uri(), snapshot_info.hash(), &target)?;

        let rel_path = self.mappings.relative(snapshot_info.uri())?;

        self.snapshot = Some(SnapshotState::create(
            notification.session_id(),
            notification.serial(),
            snapshot_info.hash(),
            rel_path,
        ));

        Ok(())
    }

    pub fn snapshot_path(&self) -> Option<PathBuf> {
        self.snapshot
            .as_ref()
            .map(|snapshot| self.mappings.path(snapshot.rel_path()))
    }

    pub fn snapshot(&self) -> Option<&SnapshotState> {
        self.snapshot.as_ref()
    }

    /// Update deltas:
    /// - deprecate old deltas
    /// - download new deltas
    /// - check limit and deprecate any surplus deltas
    fn deltas_update(
        &mut self,
        notification: &NotificationFile,
        fetcher: &Fetcher,
        delta_cut_off: u64,
        limit: Option<usize>,
    ) -> Result<()> {
        // First deprecate existing deltas. Note that 'delta_cut_off' here
        // may (will) be higher than the current notification serial if
        // a session reset occurred.
        self.deltas_deprecate_before(delta_cut_off);

        // Download new deltas, even if they would be deprecated again
        // because of a configured limit.
        for delta in notification.deltas() {
            let serial = delta.serial();

            let delta_is_new = self
                .deltas
                .front()
                .map(|highest| highest.serial() < serial)
                .unwrap_or(true);

            if delta_is_new {
                let uri = delta.uri();
                let hash = delta.hash();

                let target = self.mappings.path_for_uri(uri)?;
                fetcher.retrieve_file(uri, hash, &target)?;

                let rel_path = self.mappings.relative(uri)?;

                self.deltas
                    .push_front(DeltaState::create(serial, hash, rel_path));
            }
        }

        // Now deprecate everything that is over the limit, we do this only
        // now because we want to be sure that everything is downloaded first
        // and can be archived - if configured to do so.
        if let Some(limit) = limit {
            if let Some(highest) = self.deltas.front().map(|d| d.serial()) {
                if highest > limit as u64 {
                    let cut_off = highest - limit as u64;
                    self.deltas_deprecate_before(cut_off);
                }
            }
        }

        Ok(())
    }

    /// Remove deltas before the given serial and put them on the deprecated file list.
    ///
    /// Notes:
    /// - This may be a no-op in case all current deltas are still relevant. In that
    ///   case this function simply does nothing.
    /// - This function assumes that `self.deltas` is kept in reverse serial order.
    fn deltas_deprecate_before(&mut self, cut_off: u64) {
        let cut_off_idx_opt = self.deltas.iter().position(|c| c.serial < cut_off);

        if let Some(cut_off_idx) = cut_off_idx_opt {
            let deltas: Vec<DeltaState> = self.deltas.drain(cut_off_idx..).collect();
            for delta in deltas {
                let path = self.mappings.path(delta.rel_path());
                self.deprecated_files.push(DeprecatedFile::new(path));
            }
        }
    }
}

//------------ SourceMappings ------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationSource {
    uri: Https,
    name: String,
    etag: Option<String>,
}

impl NotificationSource {
    pub fn build(uri: Https) -> Result<Self> {
        let parent = uri
            .parent()
            .ok_or_else(|| anyhow!("Illegal notify uri: {}", uri))?;

        let name = uri
            .as_str()
            .strip_prefix(parent.as_str())
            .unwrap() // safe because we just derived the parent
            .to_string();

        Ok(NotificationSource {
            uri,
            name,
            etag: None,
        })
    }

    pub fn fetch(&mut self, fetcher: &Fetcher) -> Result<Option<NotificationFile>> {
        match fetcher.read_notification_file(self.etag.as_ref())? {
            NotificationFileResponse::Data { notification, etag } => {
                self.etag = etag;
                Ok(Some(notification))
            }
            NotificationFileResponse::Unmodified => Ok(None),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn tmp_name(&self) -> String {
        format!("{}.tmp", self.name)
    }
}

//------------ SourceMappings ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceMappings {
    /// The parent directory of the notification URI is used as the base
    /// URI for all other URIs. I.e. we insist that notification.xml file,
    /// or whatever it's called, lives in the base directory of the RRDP
    /// source and snapshots and deltas are stored under the same space.
    base_uri: Https,

    /// Base path to where the RRDP files should be saved
    rrdp_dir: PathBuf,
}

impl SourceMappings {
    pub fn build(notification_uri: Https, rrdp_dir: PathBuf) -> Result<Self> {
        let base_uri = notification_uri
            .parent()
            .ok_or_else(|| anyhow!("Illegal notification uri: {}", notification_uri))?;

        Ok(SourceMappings { base_uri, rrdp_dir })
    }

    /// Derives the relative path of the given URI versus the base URI.
    /// Returns an error in case the URI is not relative to the base URI.
    pub fn relative(&self, uri: &Https) -> Result<String> {
        uri.as_str()
            .strip_prefix(self.base_uri.as_str())
            .ok_or_else(|| anyhow!("Uri {} not relative to base uri: {}", uri, self.base_uri))
            .map(|s| s.to_string())
    }

    /// Resolve the given relative path under the base URI.
    pub fn uri(&self, rel_path: &str) -> Result<Https> {
        self.base_uri
            .join(rel_path.as_bytes())
            .map_err(|e| anyhow!("Could not resolve relative path {}, error: {}", rel_path, e))
    }

    /// Resolve the given relative path under the base RRDP directory.
    pub fn path(&self, rel_path: &str) -> PathBuf {
        self.rrdp_dir.join(rel_path)
    }

    pub fn path_for_uri(&self, uri: &Https) -> Result<PathBuf> {
        let rel_path = self.relative(uri)?;
        Ok(self.path(&rel_path))
    }
}

//------------ SnapshotState -------------------------------------------------

/// Represents a parsed and thereby reconstructed RRDP snapshot file.
/// Because the XML is reconstructed we cannot rely on the hash reported in the
/// original notification file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotState {
    #[serde(deserialize_with = "util::de_uuid", serialize_with = "util::ser_uuid")]
    session_id: Uuid,
    serial: u64,
    hash: rrdp::Hash,
    rel_path: String,
    since: Time,
}

impl SnapshotState {
    fn create(session_id: Uuid, serial: u64, hash: rrdp::Hash, rel_path: String) -> Self {
        let since = Time::now();

        SnapshotState {
            session_id,
            serial,
            hash,
            rel_path,
            since,
        }
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn rel_path(&self) -> &str {
        self.rel_path.as_str()
    }
}

//------------ DeltaState ----------------------------------------------------

/// Represents a previously fetched and saved RRDP delta file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaState {
    since: Time,
    serial: u64,
    hash: rrdp::Hash,
    rel_path: String,
}

impl DeltaState {
    fn create(serial: u64, hash: rrdp::Hash, rel_path: String) -> Self {
        let since = Time::now();

        DeltaState {
            since,
            serial,
            hash,
            rel_path,
        }
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn rel_path(&self) -> &str {
        self.rel_path.as_str()
    }
}

/// Represents a file which is no longer relevant. It can be deleted after a configurable
/// time since its deprecation has passed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeprecatedFile {
    since: Time,
    path: PathBuf,
}

impl DeprecatedFile {
    pub fn new(path: PathBuf) -> Self {
        DeprecatedFile {
            since: Time::now(),
            path,
        }
    }
}
