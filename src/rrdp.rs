use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use rpki::{
    rrdp::{
        self, Delta, DeltaElement, DeltaInfo, Hash, NotificationFile, PublishElement, Snapshot,
        SnapshotInfo, UpdateElement, WithdrawElement,
    },
    uri::{Https, Rsync},
};

use crate::{
    config::Config,
    fetch::{Fetcher, NotificationFileResponse},
    file_ops,
    util::{self, Time},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpState {
    /// The notification URI, will be used to derive the URIs for the
    /// snapshot and delta files.
    notification_uri: Https,

    /// Base path to where the RRDP files should be saved
    rrdp_dir: PathBuf,

    /// The last seen notification file etag (if seen and if set in response)
    etag: Option<String>,

    /// The identifier of the current session of the server.
    ///
    /// Delta updates can only be used if the session ID of the last processed
    /// update matches this value.
    #[serde(deserialize_with = "util::de_uuid", serialize_with = "util::ser_uuid")]
    session_id: Uuid,

    /// The serial number of the most recent update provided by the server.
    ///
    /// Serial numbers increase by one between each update.
    serial: u64,

    /// Current objects (not serialized, recovered from snapshot xml at startup)
    #[serde(skip)]
    current_objects: CurrentObjectMap,

    /// Current snapshot state (xml, hash, path)
    snapshot: SnapshotState,

    /// Delta states (xml, hash, path)
    deltas: VecDeque<DeltaState>,

    /// Deprecated files - which may be cleaned up after some time
    deprecated_files: Vec<DeprecatedFile>,
}

impl RrdpState {
    /// Build up a new RrdpState, i.e. without prior state.
    pub fn create(config: &Config) -> Result<Self> {
        info!("No prior state found, will build up state from latest snapshot at source");
        let notification_uri = config.notification_uri.clone();
        let rrdp_dir = config.rrdp_dir.clone();

        let fetcher = config.fetcher();

        let (mut notification_file, etag) = fetcher.read_notification_file(None)?.content()?;

        let session_id = notification_file.session_id();
        let serial = notification_file.serial();

        let current_objects =
            CurrentObjectMap::read_snapshot(notification_file.snapshot(), &fetcher)?;

        // Recreate a new snapshot and XML to ensure that the order and formatting matches
        // snapshots derived from applying updates.
        let snapshot = current_objects.derive_snapshot(session_id, serial);

        if !notification_file.sort_and_verify_deltas() {
            return Err(anyhow!("Notification file contained gaps in deltas"));
        }

        let deltas = Self::read_deltas(notification_file.deltas(), &fetcher)?;

        info!("Done building up state");

        Ok(RrdpState {
            notification_uri,
            rrdp_dir,
            etag,
            session_id,
            serial,
            current_objects,
            snapshot,
            deltas,
            deprecated_files: vec![],
        })
    }

    /// Recover from disk. Reads the last known state from disk and re-parses the current snapshot
    /// and all delta files. Returns an error if any of this fails.
    pub fn recover(state_path: &Path) -> Result<Self> {
        debug!("Recovering prior state");
        let json_bytes = file_ops::read_file(state_path)
            .with_context(|| format!("Cannot read state file at: {:?}", state_path))?;

        // Recover state with meta info from disk.
        let mut recovered: RrdpState =
            serde_json::from_slice(json_bytes.as_ref()).with_context(|| {
                format!(
                    "Cannot deserialize json for current state from {:?}",
                    state_path
                )
            })?;

        // Now reload and parse all xml files
        recovered.recover_snapshot()?;
        recovered.recover_deltas()?;

        info!(
            "Recovered prior state => session: {}, serial: {}",
            recovered.session_id(),
            recovered.serial()
        );
        Ok(recovered)
    }

    fn recover_snapshot(&mut self) -> Result<()> {
        debug!(
            "Recover and verify snapshot for session {} and serial {}",
            self.session_id(),
            self.serial()
        );
        let snapshot_path = Self::path_snapshot(&self.rrdp_dir, self.session_id(), self.serial());
        let snapshot_bytes = file_ops::read_file(&snapshot_path)
            .with_context(|| format!("Cannot read snapshot from {:?}", snapshot_path))?;

        debug!("Parse snapshot");
        let snapshot = Snapshot::parse(snapshot_bytes.as_ref())
            .with_context(|| format!("Cannot parse snapshot from {:?}", snapshot_path))?;

        debug!("Converting snapshot into elements");
        self.current_objects = snapshot.into_elements().into();

        debug!("Set xml");
        self.snapshot.set_xml(snapshot_bytes);

        Ok(())
    }

    fn recover_deltas(&mut self) -> Result<()> {
        let base_dir = self.rrdp_dir.clone();
        let session = self.session_id();

        for delta in self.deltas.iter_mut() {
            debug!(
                "Recover and verify delta for session {} and serial {}",
                session, delta.serial
            );
            let delta_path = Self::path_delta(&base_dir, session, delta.serial);

            let delta_bytes = file_ops::read_file(&delta_path)
                .with_context(|| format!("Cannot read delta file from {:?}", delta_path))?;

            Delta::parse(delta_bytes.as_ref())
                .with_context(|| format!("Cannot parse delta file from {:?}", delta_path))?;

            delta.set_xml(delta_bytes);
        }

        Ok(())
    }

    /// Try to update this state using the notification file found in the specified fetcher.
    /// Returns:
    ///   Ok(true)  if there was an update
    ///   Ok(false) if there was no update (serial and session match current)
    ///   Err       if there was an error trying to update
    pub fn update(&mut self, fetcher: &Fetcher) -> Result<bool> {
        match fetcher.read_notification_file(self.etag.as_ref())? {
            NotificationFileResponse::Unmodified => {
                info!("Notification file was not changed, no updated needed.");
                Ok(false)
            }
            NotificationFileResponse::Data {
                mut notification,
                etag,
            } => {
                // If we got a response, then update our local etag. No matter whether we can actually use
                // this response, we will have seen it, so there is no point in trying again later.
                // If the etag is now NONE, but it was set before then we should also forget it locally. This
                // is a bit strange but perhaps the server just dropped support for etag?
                self.etag = etag;

                // Now see what we can do with the new notification file.
                if !notification.sort_and_verify_deltas() {
                    Err(anyhow!("Notification file contained gaps in deltas"))
                } else if notification.session_id() != self.session_id {
                    info!("Session reset by source, will apply new snapshot");
                    self.apply_snapshot(notification, fetcher)?;
                    Ok(true)
                } else if notification.serial() == self.serial {
                    // Note, this smells like an unmodified notification, but then again the server
                    // may not support etag so we need to check.
                    info!("No update of RRDP needed at this time");
                    Ok(false)
                } else if notification.serial() < self.serial {
                    Err(anyhow!(format!(
                        "The notification file serial '{}' is *before* our serial '{}'",
                        notification.serial(),
                        self.serial
                    )))
                } else {
                    let has_delta_path = notification
                        .deltas()
                        .first()
                        .map(|first| first.serial() <= self.serial)
                        .unwrap_or(false);

                    if has_delta_path {
                        info!("New notification file found, will apply deltas to local state");
                        self.apply_deltas(notification, fetcher)?;
                    } else {
                        info!("New notification file found, cannot apply deltas to local state, will use snapshot");
                        self.apply_snapshot(notification, fetcher)?;
                    }

                    Ok(true)
                }
            }
        }
    }

    /// Update the current state by applying deltas.
    fn apply_deltas(
        &mut self,
        notification_file: NotificationFile,
        fetcher: &Fetcher,
    ) -> Result<()> {
        self.deprecate_snapshot_file();

        let lowest_delta_serial = notification_file
            .deltas()
            .first()
            .ok_or_else(|| anyhow!("Apply deltas was called with an empty delta list"))?
            .serial();

        self.deprecate_deltas_before(lowest_delta_serial);

        // Process all deltas. Note we can assume that the caller ordered these
        // deltas by serial and verified they contain no gaps.
        for delta_info in notification_file.deltas() {
            if delta_info.serial() > self.serial {
                self.apply_delta(delta_info, fetcher)?;
            }
        }

        self.snapshot = self
            .current_objects
            .derive_snapshot(self.session_id, self.serial);

        Ok(())
    }

    /// Remove deltas before the given serial and put them on the deprecated file list.
    ///
    /// Notes:
    /// - This may be a no-op in case all current deltas are still relevant. In that
    ///   case this function simply does nothing.
    /// - This function assumes that `self.deltas` is kept in reverse serial order.
    fn deprecate_deltas_before(&mut self, before: u64) {
        let cut_off_idx_opt = self.deltas.iter().position(|c| c.serial < before);

        if let Some(cut_off_idx) = cut_off_idx_opt {
            let mut delta_serials_remove = vec![];
            for delta in self.deltas.drain(cut_off_idx..) {
                delta_serials_remove.push(delta.serial())
            }
            for serial in delta_serials_remove {
                self.deprecate_delta_file(serial);
            }
        }
    }

    /// Download and apply the `Delta` for the given `DeltaInfo`.
    ///
    /// Will fail if the Delta:
    ///  - is not for the next serial
    ///  - could not be retrieved
    ///  - does not match the hash
    ///  - cannot be applied to the current elements:
    ///      -- remove or update an element which is not present
    ///      -- add an element which is present
    fn apply_delta(&mut self, delta_info: &DeltaInfo, fetcher: &Fetcher) -> Result<()> {
        if self.serial != delta_info.serial() - 1 {
            Err(anyhow!(format!(
                "Cannot apply delta for serial '{}' to state serial '{}'",
                delta_info.serial(),
                self.serial()
            )))
        } else {
            info!("Applying delta for serial: {}", delta_info.serial());
            let delta = fetcher.read_delta_file(delta_info)?;
            let delta_state = DeltaState::create(&delta);
            self.current_objects.apply_delta(delta)?;
            self.deltas.push_front(delta_state);
            self.serial += 1;
            Ok(())
        }
    }

    /// Reads all deltas from a notification file, and returns a sorted
    /// VecDeque of DeltaInfo. Used when the actual RRDP current state is
    /// derived from a snapshot, but all deltas on notification file need
    /// to be downloaded so that they may be made available.
    fn read_deltas(deltas: &[DeltaInfo], fetcher: &Fetcher) -> Result<VecDeque<DeltaState>> {
        let mut res = VecDeque::new();

        for delta in deltas {
            debug!("Read delta from {}", delta.uri());
            let delta = fetcher.read_delta_file(delta)?;
            let delta = DeltaState::create(&delta);
            res.push_front(delta);
        }

        Ok(res)
    }

    /// Update state using a new snapshot
    fn apply_snapshot(
        &mut self,
        notification_file: NotificationFile,
        fetcher: &Fetcher,
    ) -> Result<()> {
        self.deprecate_snapshot_file();
        self.deprecate_deltas_before(self.serial + 1);

        self.serial = notification_file.serial();
        self.session_id = notification_file.session_id(); // could have been reset.

        self.current_objects =
            CurrentObjectMap::read_snapshot(notification_file.snapshot(), fetcher)?;
        self.snapshot = self
            .current_objects
            .derive_snapshot(self.session_id(), self.serial());
        self.deltas = Self::read_deltas(notification_file.deltas(), fetcher)?;

        Ok(())
    }

    /// Write out all *missing* RRDP files. Optionally delay writing the notification file for
    /// the specified number of seconds
    pub fn write_rrdp_files(&self, notify_delay: u64) -> Result<()> {
        self.write_snapshot()?;
        self.write_missing_deltas()?;

        if notify_delay > 0 {
            info!(
                "Waiting {} seconds before writing RRDP notification file",
                notify_delay
            );
            std::thread::sleep(std::time::Duration::from_secs(notify_delay));
        }
        self.write_notification()?;

        Ok(())
    }

    /// Cleans deprecated files and their parent directories if they are empty
    pub fn clean(&mut self, config: &Config) -> Result<()> {
        let clean_before = Time::seconds_ago(config.cleanup_after);

        for deprecated in self
            .deprecated_files
            .iter()
            .filter(|d| d.since < clean_before)
        {
            let path = &deprecated.path;
            if path.exists() {
                info!(
                    "Removing RRDP file: {:?}, deprecated since: {}",
                    path, deprecated.since
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

        file_ops::write_buf(path, json.as_bytes()).with_context(|| "Could not save state.")
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn elements(&self) -> impl Iterator<Item = &CurrentObject> {
        self.current_objects.objects()
    }

    /// Writes the notification file to disk. Will first write to a
    /// temporary file and then rename it to avoid serving partially
    /// written files.
    pub fn write_notification(&self) -> Result<()> {
        let tmp_path = self.rrdp_dir.join(".notification.xml");
        let final_path = self.rrdp_dir.join("notification.xml");

        info!("Updating notification file at {:?}", final_path);

        let notification = self.make_notification_file()?;

        let mut bytes: Vec<u8> = vec![];
        let mut writer = rpki::xml::encode::Writer::new_with_indent(&mut bytes);
        notification.to_xml(&mut writer)?;

        file_ops::write_buf(&tmp_path, &bytes)
            .with_context(|| "Could not write temporary notification file")?;

        fs::rename(tmp_path, final_path)
            .with_context(|| "Could not rename tmp notification file to real notification file")?;

        Ok(())
    }

    fn make_notification_file(&self) -> Result<NotificationFile> {
        let base_uri = self
            .notification_uri
            .parent()
            .ok_or_else(|| anyhow!("Notification URI does not have a parent?!"))?;

        let rel_path_snapshot = Self::rel_path_snapshot(self.session_id(), self.serial());

        let snapshot_uri = base_uri
            .join(rel_path_snapshot.as_bytes())
            .with_context(|| "Could not derive snapshot URI")?;

        let snapshot_hash = self.snapshot.hash();
        let snapshot_info = SnapshotInfo::new(snapshot_uri, snapshot_hash);

        let mut deltas = vec![];
        for delta in &self.deltas {
            let serial = delta.serial();
            let hash = delta.hash();
            let rel_path_delta = Self::rel_path_delta(self.session_id(), serial);
            let uri = base_uri
                .join(rel_path_delta.as_bytes())
                .with_context(|| "Could not derive delta URI")?;

            deltas.push(DeltaInfo::new(serial, uri, hash));
        }

        Ok(NotificationFile::new(
            self.session_id,
            self.serial,
            snapshot_info,
            deltas,
        ))
    }

    /// Marks a snapshot file as deprecated. Assumes that the session id is still unchanged. If the
    /// there would be a session id reset, then deprecate files for the old session id first, before
    /// updating the current session id.
    fn deprecate_snapshot_file(&mut self) {
        let path = Self::path_snapshot(&self.rrdp_dir, self.session_id(), self.serial());
        self.deprecated_files.push(DeprecatedFile::new(path));
    }

    /// Writes a new notification file. Will not check whether the file already
    /// exists because this is assumed to be called for new snapshot files only.
    fn write_snapshot(&self) -> Result<()> {
        let path = Self::path_snapshot(&self.rrdp_dir, self.session_id(), self.serial());
        if path.exists() {
            debug!("Skip writing existing snapshot file to {:?}", path)
        } else {
            info!("Writing snapshot file to {:?}", path);
            let xml = self
                .snapshot
                .xml()
                .ok_or_else(|| anyhow!("Snapshot XML not recovered on startup"))?;
            file_ops::write_buf(&path, xml).with_context(|| "Could not write snapshot XML")?;
        }

        Ok(())
    }

    /// Marks a delta file as deprecated. Assumes that the session id is still unchanged. If the
    /// there would be a session id reset, then deprecate files for the old session id first, before
    /// updating the current session id.
    fn deprecate_delta_file(&mut self, serial: u64) {
        let path = Self::path_delta(&self.rrdp_dir, self.session_id(), serial);
        self.deprecated_files.push(DeprecatedFile::new(path));
    }

    /// Writes any deltas for which no current file is found. I.e. it is assumed
    /// that a file which is present was not tampered with since writing it.
    fn write_missing_deltas(&self) -> Result<()> {
        for delta in &self.deltas {
            let path = Self::path_delta(&self.rrdp_dir, self.session_id(), delta.serial);
            if path.exists() {
                debug!("Skip writing delta file to {:?}", path)
            } else {
                info!("Writing delta file to {:?}", path);
                let xml = delta
                    .xml()
                    .ok_or_else(|| anyhow!("Delta XML not recovered on startup"))?;
                file_ops::write_buf(&path, xml).with_context(|| "Could not write delta XML")?;
            }
        }

        Ok(())
    }

    fn path_snapshot(base_dir: &Path, session: Uuid, serial: u64) -> PathBuf {
        base_dir.join(Self::rel_path_snapshot(session, serial))
    }

    fn path_delta(base_dir: &Path, session: Uuid, serial: u64) -> PathBuf {
        base_dir.join(Self::rel_path_delta(session, serial))
    }

    fn rel_path_snapshot(session: Uuid, serial: u64) -> String {
        format!("{}/{}/snapshot.xml", session, serial)
    }

    fn rel_path_delta(session: Uuid, serial: u64) -> String {
        format!("{}/{}/delta.xml", session, serial)
    }
}

//------------ CurrentObjectMap ----------------------------------------------
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentObjectMap(HashMap<String, CurrentObject>);

impl CurrentObjectMap {
    /// Create a new CurrentObjectMap by reading and parsing a snapshot file
    fn read_snapshot(info: &SnapshotInfo, fetcher: &Fetcher) -> Result<Self> {
        debug!("Reading snapshot from {}", info.uri());
        let snapshot = fetcher.read_snapshot_file(info)?;
        Ok(snapshot.into_elements().into())
    }

    /// Derive a new Snapshot. Order the objects by URI.
    fn derive_snapshot(&self, session: Uuid, serial: u64) -> SnapshotState {
        let mut publishes: Vec<PublishElement> = self
            .0
            .values()
            .map(|current| PublishElement::new(current.uri().clone(), current.data().clone()))
            .collect();
        publishes.sort_by_key(|p| p.uri().to_string());

        let snapshot = Snapshot::new(session, serial, publishes);
        SnapshotState::create(&snapshot)
    }

    /// Apply an RRDP delta to self
    fn apply_delta(&mut self, delta: Delta) -> Result<()> {
        for el in delta.into_elements() {
            match el {
                DeltaElement::Publish(publish) => self.apply_publish(publish)?,
                DeltaElement::Update(update) => self.apply_update(update)?,
                DeltaElement::Withdraw(withdraw) => self.apply_withdraw(withdraw)?,
            }
        }
        Ok(())
    }

    fn apply_publish(&mut self, publish: PublishElement) -> Result<()> {
        let object: CurrentObject = publish.into();
        #[allow(clippy::map_entry)]
        if self.0.contains_key(object.uri().as_str()) {
            Err(anyhow!(format!(
                "Object with uri '{}' cannot be added (already present)",
                object.uri()
            )))
        } else {
            self.0.insert(object.uri().to_string(), object);
            Ok(())
        }
    }

    fn apply_update(&mut self, update: UpdateElement) -> Result<()> {
        let (uri, replaces, data) = update.unpack();
        let object = CurrentObject { uri, data };

        let old = self.0.get(object.uri().as_str()).ok_or_else(|| {
            anyhow!(format!(
                "Object for uri '{}' cannot be updated: not present",
                object.uri()
            ))
        })?;

        if old.hash() != replaces {
            Err(anyhow!(format!(
                "Object for uri '{}' cannot be updated: hash mismatch",
                object.uri()
            )))
        } else {
            self.0.insert(object.uri().to_string(), object);
            Ok(())
        }
    }

    fn apply_withdraw(&mut self, withdraw: WithdrawElement) -> Result<()> {
        let (uri, hash) = withdraw.unpack();

        let old = self.0.get(uri.as_str()).ok_or_else(|| {
            anyhow!(format!(
                "Object for uri '{}' cannot be removed: was not present",
                uri
            ))
        })?;

        if old.hash() != hash {
            Err(anyhow!(format!(
                "Object for uri '{}' cannot be withdrawn: hash mismatch",
                uri
            )))
        } else {
            self.0.remove(uri.as_str());
            Ok(())
        }
    }
}

impl CurrentObjectMap {
    pub fn objects(&self) -> impl Iterator<Item = &CurrentObject> {
        self.0.values()
    }
}

impl Default for CurrentObjectMap {
    fn default() -> Self {
        CurrentObjectMap(HashMap::new())
    }
}

impl From<Vec<PublishElement>> for CurrentObjectMap {
    fn from(elements: Vec<PublishElement>) -> Self {
        #[allow(clippy::mutable_key_type)]
        let mut map = HashMap::new();
        for el in elements.into_iter() {
            let current_object: CurrentObject = el.into();
            map.insert(current_object.uri().to_string(), current_object);
        }
        CurrentObjectMap(map)
    }
}

//------------ CurrentObject -------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CurrentObject {
    uri: Rsync,
    data: Bytes,
}

impl CurrentObject {
    pub fn uri(&self) -> &Rsync {
        &self.uri
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn hash(&self) -> Hash {
        Hash::from_data(&self.data)
    }
}

impl From<PublishElement> for CurrentObject {
    fn from(el: PublishElement) -> Self {
        let (uri, data) = el.unpack();
        CurrentObject { uri, data }
    }
}

//------------ SnapshotState -------------------------------------------------

/// Represents a parsed and thereby reconstructed RRDP snapshot file.
/// Because the XML is reconstructed we cannot rely on the hash reported in the
/// original notification file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotState {
    since: Time,
    hash: rrdp::Hash,

    #[serde(skip)]
    xml: Option<Bytes>,
}

impl SnapshotState {
    fn create(snapshot: &Snapshot) -> Self {
        let mut bytes: Vec<u8> = vec![];
        let mut writer = rpki::xml::encode::Writer::new_with_indent(&mut bytes);
        snapshot.to_xml(&mut writer).unwrap(); // cannot fail
        let xml: Bytes = bytes.into();

        let since = Time::now();
        let hash = rrdp::Hash::from_data(xml.as_ref());

        SnapshotState {
            xml: Some(xml),
            since,
            hash,
        }
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn xml(&self) -> Option<&Bytes> {
        self.xml.as_ref()
    }

    fn set_xml(&mut self, bytes: Bytes) {
        self.xml = Some(bytes);
    }
}

//------------ DeltaState ----------------------------------------------------

/// Represents a parsed and thereby reconstructed RRDP delta file.
/// Because the XML is reconstructed we cannot rely on the hash reported in the
/// original notification file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaState {
    since: Time,
    serial: u64,
    hash: rrdp::Hash,

    #[serde(skip)]
    xml: Option<Bytes>,
}

impl DeltaState {
    fn create(delta: &Delta) -> Self {
        let since = Time::now();
        let serial = delta.serial();

        let mut bytes: Vec<u8> = vec![];
        let mut writer = rpki::xml::encode::Writer::new_with_indent(&mut bytes);
        delta.to_xml(&mut writer).unwrap(); // cannot fail
        let xml: Bytes = bytes.into();

        let hash = rrdp::Hash::from_data(xml.as_ref());

        DeltaState {
            since,
            serial,
            hash,
            xml: Some(xml),
        }
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn xml(&self) -> Option<&Bytes> {
        self.xml.as_ref()
    }

    fn set_xml(&mut self, bytes: Bytes) {
        self.xml = Some(bytes);
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

#[cfg(test)]
mod tests {
    use crate::config::create_test_config;
    use crate::util::{https, test_with_dir};

    use super::*;

    #[test]
    fn process_update_no_change() {
        test_with_dir("rrdp_state_process_update_no_change", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let config = create_test_config(&dir, notification_uri, source_uri_base);

            // Build state from source
            let state = RrdpState::create(&config).unwrap();

            let mut updated = state.clone();
            updated.update(&config.fetcher()).unwrap();

            assert_eq!(state, updated);
        })
    }

    #[test]
    fn process_update_delta() {
        test_with_dir("rrdp_state_process_update_delta", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let config = create_test_config(&dir, notification_uri, source_uri_base);

            // Build state from source
            let state = RrdpState::create(&config).unwrap();
            state.write_rrdp_files(0).unwrap();
            state.persist(&config.state_path()).unwrap();

            // Recover
            let mut recovered = RrdpState::recover(&config.state_path()).unwrap();
            assert_eq!(state, recovered);

            // Update
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base_2658 = "./test-resources/rrdp-rev2658/";
            let config_2658 = create_test_config(&dir, notification_uri, source_uri_base_2658);

            recovered.update(&config_2658.fetcher()).unwrap();

            let from_clean_2657 = RrdpState::create(&config_2658).unwrap();

            assert_ne!(recovered, from_clean_2657); // recovered includes deprecated snapshot

            assert_eq!(recovered.snapshot.hash, from_clean_2657.snapshot.hash);

            let recovered_delta_hashes: Vec<Hash> =
                recovered.deltas.iter().map(|d| d.hash()).collect();
            let from_clean_delta_hashes: Vec<Hash> =
                from_clean_2657.deltas.iter().map(|d| d.hash()).collect();
            assert_eq!(recovered_delta_hashes, from_clean_delta_hashes);
        })
    }

    #[test]
    fn process_update_no_delta() {
        test_with_dir("rrdp_state_process_update_no_delta", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let config = create_test_config(&dir, notification_uri, source_uri_base);

            // Build state from source
            let state = RrdpState::create(&config).unwrap();
            state.write_rrdp_files(0).unwrap();
            state.persist(&config.state_path()).unwrap();

            // Recover
            let mut recovered = RrdpState::recover(&config.state_path()).unwrap();
            assert_eq!(state, recovered);

            // Update
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base_2658 = "./test-resources/rrdp-rev2658-no-delta/";
            let config_2658 = create_test_config(&dir, notification_uri, source_uri_base_2658);

            recovered.update(&config_2658.fetcher()).unwrap();

            let from_clean_2658 = RrdpState::create(&config_2658).unwrap();

            assert_ne!(recovered, from_clean_2658); // recovered includes deprecated snapshot

            assert_eq!(recovered.snapshot.hash, from_clean_2658.snapshot.hash);

            let recovered_delta_hashes: Vec<Hash> =
                recovered.deltas.iter().map(|d| d.hash()).collect();
            let from_clean_delta_hashes: Vec<Hash> =
                from_clean_2658.deltas.iter().map(|d| d.hash()).collect();
            assert_eq!(recovered_delta_hashes, from_clean_delta_hashes);
        })
    }

    #[test]
    fn process_update_session_reset() {
        test_with_dir("rrdp_state_process_update_session_reset", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let config = create_test_config(&dir, notification_uri, source_uri_base);

            // Build state from source
            let state = RrdpState::create(&config).unwrap();
            state.write_rrdp_files(0).unwrap();
            state.persist(&config.state_path()).unwrap();

            // Recover
            let mut recovered = RrdpState::recover(&config.state_path()).unwrap();
            assert_eq!(state, recovered);

            // Update
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base_session_reset = "./test-resources/rrdp-rev2-session-reset/";
            let config_session_reset =
                create_test_config(&dir, notification_uri, source_uri_base_session_reset);

            recovered.update(&config_session_reset.fetcher()).unwrap();

            let from_clean_session_reset = RrdpState::create(&config_session_reset).unwrap();

            assert_ne!(recovered, from_clean_session_reset); // recovered includes deprecated snapshot

            assert_eq!(
                recovered.snapshot.hash,
                from_clean_session_reset.snapshot.hash
            );

            let recovered_delta_hashes: Vec<Hash> =
                recovered.deltas.iter().map(|d| d.hash()).collect();
            let from_clean_delta_hashes: Vec<Hash> = from_clean_session_reset
                .deltas
                .iter()
                .map(|d| d.hash())
                .collect();
            assert_eq!(recovered_delta_hashes, from_clean_delta_hashes);
        })
    }
}
