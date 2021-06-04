use std::{collections::{HashMap, VecDeque}, fs, path::{Path, PathBuf}};

use anyhow::{Context, Result};
use bytes::Bytes;

use rpki::{rrdp::{self, Delta, DeltaElement, DeltaInfo, Hash, NotificationFile, PublishElement, Snapshot, SnapshotInfo, UpdateElement, WithdrawElement}, uri::{Https, Rsync}};
use uuid::Uuid;

use crate::{
    config::Config,
    fetch::Fetcher,
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
        let notification_uri = config.notification_uri.clone();
        let rrdp_dir = config.rrdp_dir.clone();

        let fetcher = config.fetcher();
        let mut notification_file = fetcher.read_notification_file()?;

        let session_id = notification_file.session_id();
        let serial = notification_file.serial();

        let snapshot_info = notification_file.snapshot();

        let snapshot_org = fetcher.read_snapshot_file(snapshot_info.uri(), snapshot_info.hash())?;
        let current_objects: CurrentObjectMap = snapshot_org.into_elements().into();

        // Recreate a new snapshot and XML to ensure that the order and formatting matches
        // snapshots derived from applying updates.
        let snapshot = current_objects.derive_snapshot(session_id, serial);
        let snapshot = SnapshotState::create(&snapshot)?;

        if !notification_file.sort_and_verify_deltas() {
            return Err(anyhow!("Notification file contained gaps in deltas"));
        }
        let mut deltas = VecDeque::new();
        for delta in notification_file.deltas() {
            let delta = fetcher.read_delta_file(delta)?;
            let delta = DeltaState::create(&delta)?;
            deltas.push_front(delta);
        }

        Ok(RrdpState {
            notification_uri,
            rrdp_dir,
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

        Ok(recovered)
    }

    fn recover_snapshot(&mut self) -> Result<()> {
        let snapshot_path = Self::path_snapshot(&self.rrdp_dir, self.session_id(), self.serial());
        let snapshot_bytes = file_ops::read_file(&snapshot_path)
            .with_context(|| format!("Cannot read snapshot from {:?}", snapshot_path))?;

        let snapshot = Snapshot::parse(snapshot_bytes.as_ref())
            .with_context(|| format!("Cannot parse snapshot from {:?}", snapshot_path))?;

        self.current_objects = snapshot.into_elements().into();

        self.snapshot.set_xml(snapshot_bytes);

        Ok(())
    }

    fn recover_deltas(&mut self) -> Result<()> {
        let base_dir = self.rrdp_dir.clone();
        let session = self.session_id();

        for delta in self.deltas.iter_mut() {
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
        let mut notification_file = fetcher.read_notification_file()?;
        if !notification_file.sort_and_verify_deltas() {
            Err(anyhow!("Notification file contained gaps in deltas"))
        } else if notification_file.session_id() != self.session_id {
            info!("Session reset by source, will apply new snapshot");
            self.apply_snapshot(notification_file, fetcher)?;
            Ok(true)
        } else if notification_file.serial() == self.serial {
            debug!("No update of RRDP needed at this time");
            Ok(false)
        } else if notification_file.serial() < self.serial {
            Err(anyhow!(format!(
                "The notification file serial '{}' is *before* our serial '{}'",
                notification_file.serial(),
                self.serial
            )))
        } else {
            let has_delta_path = notification_file.deltas().first()
                .map(|first| first.serial() <= self.serial)
                .unwrap_or(false);

            if has_delta_path {
                info!("New notification file found, will apply deltas to local state");
                self.apply_deltas(notification_file, fetcher)?;
            } else {
                info!("New notification file found, cannot apply deltas to local state, will use snapshot");
                self.apply_snapshot(notification_file, fetcher)?;
            }

            Ok(true)
        }
    }

    /// Update the current state by applying deltas. I.e.:
    /// - derive new snapshot
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
    
        self.deprecate_deltas_before(lowest_delta_serial)?;
        
        // Process all deltas. Note we can assume that the caller ordered these
        // deltas by serial and verified they contain no gaps.
        for delta_info in notification_file.deltas() {
            if delta_info.serial() > self.serial {
                self.apply_delta(delta_info, fetcher)?;
            }
        }
        
        self.derive_snapshot()?;
        
        Ok(())
    }
            
    /// Remove deltas before the given serial and put them on the deprecated file list. 
    /// 
    /// Notes:
    /// - This may be a no-op in case all current deltas are still relevant. In that
    ///   case this function simply does nothing.
    /// - This function assumes that `self.deltas` is kept in reverse serial order.
    fn deprecate_deltas_before(&mut self, before: u64) -> Result<()> {
        let cut_off_idx_opt = self
            .deltas
            .iter()
            .position(|c| c.serial < before);
        
        if let Some(cut_off_idx) = cut_off_idx_opt {
            let mut delta_serials_remove = vec![];
            for delta in self.deltas.drain(cut_off_idx..) {
                delta_serials_remove.push(delta.serial())
            }
            for serial in delta_serials_remove {
                self.deprecate_delta_file(serial);
            }
        }
        
        Ok(())
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
                self.serial())))
        } else {
            let delta = fetcher.read_delta_file(delta_info)?;
            let delta_state = DeltaState::create(&delta)?;
            self.current_objects.apply_delta(delta)?;
            self.deltas.push_front(delta_state);
            self.serial += 1;
            Ok(())
        }
    }

    /// Derive the snapshot held by this state
    pub fn derive_snapshot(&mut self) -> Result<()> {
        let snapshot = self.current_objects.derive_snapshot(self.session_id, self.serial);
        self.snapshot = SnapshotState::create(&snapshot)?;
        Ok(())
    }
                
    /// Update state using a new snapshot
    /// - move snapshot to clean up list
    /// - move all current deltas to clean up list
    /// - parse snapshot and all deltas
    /// - update the current elements
    fn apply_snapshot(
        &mut self,
        notification_file: NotificationFile,
        fetcher: &Fetcher,
    ) -> Result<()> {
        self.deprecate_snapshot_file();
        todo!("apply snap")
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

    pub fn elements(&self) -> impl Iterator<Item=&CurrentObject> {
        self.current_objects.objects()
    }

    /// Writes the notification file to disk. Will first write to a
    /// temporary file and then rename it to avoid serving partially
    /// written files.
    pub fn write_notification(&self) -> Result<()> {
        let tmp_path = self.rrdp_dir.join(".notification.xml");
        let final_path = self.rrdp_dir.join("notification.xml");

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
        let xml = self
            .snapshot
            .xml()
            .ok_or_else(|| anyhow!("Snapshot XML not recovered on startup"))?;
        file_ops::write_buf(&path, xml).with_context(|| "Could not write snapshot XML")?;

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
                info!("Write delta file to {:?}", path);
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
pub struct CurrentObjectMap(HashMap<Rsync, CurrentObject>);

impl CurrentObjectMap {
    /// Derive a new Snapshot. Order the objects by URI.
    fn derive_snapshot(&self, session: Uuid, serial: u64) -> Snapshot {

        let mut publishes: Vec<PublishElement> = self.0.values().map(|current|
            PublishElement::new(current.uri().clone(), current.data().clone())
        ).collect();
        publishes.sort_by_key(|p| p.uri().to_string());
        
        Snapshot::new(session, serial, publishes)
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
        if self.0.contains_key(object.uri()) {
            Err(anyhow!(format!("Object with uri '{}' cannot be added (already present)", object.uri())))
        } else {
            self.0.insert(object.uri().clone(), object);
            Ok(())
        }
    }

    fn apply_update(&mut self, update: UpdateElement) -> Result<()> {
        let (uri, replaces, data) = update.unpack();
        let object = CurrentObject { uri, data };

        let old = self.0.get(object.uri()).ok_or_else(||
            anyhow!(format!("Object for uri '{}' cannot be updated: not present", object.uri()))
        )?;

        if old.hash() != replaces {
            Err(anyhow!(format!("Object for uri '{}' cannot be updated: hash mismatch", object.uri())))
        } else {
            self.0.remove(object.uri());
            self.0.insert(object.uri().clone(), object);
            Ok(())
        }
        
    }

    fn apply_withdraw(&mut self, withdraw: WithdrawElement) -> Result<()> {
        let (uri, hash) = withdraw.unpack();
        
        let old = self.0.get(&uri).ok_or_else(||
            anyhow!(format!("Object for uri '{}' cannot be removed: was not present", uri))
        )?;

        if old.hash() != hash {
            Err(anyhow!(format!("Object for uri '{}' cannot be withdrawn: hash mismatch", uri)))
        } else {
            self.0.remove(&uri);
            Ok(())
        }
        
    }
}

impl CurrentObjectMap {
    pub fn objects(&self) -> impl Iterator<Item=&CurrentObject> {
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
        let mut map = HashMap::new();
        for el in elements.into_iter() {
            let current_object: CurrentObject = el.into();
            map.insert(current_object.uri().clone(), current_object);
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
    fn create(snapshot: &Snapshot) -> Result<Self> {
        let mut bytes: Vec<u8> = vec![];
        let mut writer = rpki::xml::encode::Writer::new_with_indent(&mut bytes);
        snapshot.to_xml(&mut writer)?;
        let xml: Bytes = bytes.into();

        let since = Time::now();
        let hash = rrdp::Hash::from_data(xml.as_ref());

        Ok(SnapshotState {
            xml: Some(xml),
            since,
            hash,
        })
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
    fn create(delta: &Delta) -> Result<Self> {
        let since = Time::now();
        let serial = delta.serial();

        let mut bytes: Vec<u8> = vec![];
        let mut writer = rpki::xml::encode::Writer::new_with_indent(&mut bytes);
        delta.to_xml(&mut writer)?;
        let xml: Bytes = bytes.into();

        let hash = rrdp::Hash::from_data(xml.as_ref());

        Ok(DeltaState {
            since,
            serial,
            hash,
            xml: Some(xml),
        })
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
    fn build_and_recover() {
        test_with_dir("rrdp_state_build_and_recover", |dir| {
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
            let notification_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base_2657 = "./test-resources/rrdp-rev2657/";
            let config_2657 = create_test_config(&dir, notification_uri, source_uri_base_2657);
            
            recovered.update(&config_2657.fetcher()).unwrap();
            
            let from_clean_2657 = RrdpState::create(&config_2657).unwrap();

            assert_ne!(recovered, from_clean_2657); // recovered includes deprecated snapshot

            assert_eq!(recovered.snapshot.hash, from_clean_2657.snapshot.hash);

            let recovered_delta_hashes: Vec<Hash> = recovered.deltas.iter().map(|d|d.hash()).collect();
            let from_clean_delta_hashes: Vec<Hash> = from_clean_2657.deltas.iter().map(|d|d.hash()).collect();
            assert_eq!(recovered_delta_hashes, from_clean_delta_hashes);
        })
    }
}

// //------------ RrdpProcessError ----------------------------------------------

// #[derive(Debug)]
// pub enum RrdpProcessError {
//     Xml(XmlError),
//     ProcessError(ProcessError),
// }

// impl From<XmlError> for RrdpProcessError {
//     fn from(err: XmlError) -> Self {
//         RrdpProcessError::Xml(err)
//     }
// }

// impl From<ProcessError> for RrdpProcessError {
//     fn from(err: ProcessError) -> Self {
//         RrdpProcessError::ProcessError(err)
//     }
// }

// impl From<io::Error> for RrdpProcessError {
//     fn from(err: io::Error) -> Self {
//         RrdpProcessError::ProcessError(ProcessError::from(err))
//     }
// }

// impl fmt::Display for RrdpProcessError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             RrdpProcessError::Xml(ref err) => err.fmt(f),
//             RrdpProcessError::ProcessError(err) => err.fmt(f),
//         }
//     }
// }

// impl std::error::Error for RrdpProcessError { }

// // use crate::config::{self, Opt};
// // use crate::file_ops;
// // use crate::http::{self, DownloadResult, HttpClient, Https, DownloadType};
// // use crate::state::State;

// // use anyhow::{anyhow, Context, Result};
// // use ring::digest;
// // use routinator::rpki::uri;
// // use routinator::rpki::rrdp::{
// //     DigestHex, ProcessDelta, ProcessSnapshot, UriAndHash
// // };
// // use routinator::rpki::xml::decode::Error as XmlDecodeError;
// // use uuid::Uuid;

// // use std::collections::HashMap;
// // use std::path::PathBuf;
// // use std::io::BufReader;
// // use std::str::FromStr;

// // pub use routinator::rpki::rrdp::NotificationFile;
// // struct ParsedMeta {
// //     pub session_id: Uuid,
// //     pub serial: u64,
// // }

// // // Store deltas as a HashMap because there can be many deltas (e.g. >1000 in the
// // // case of https://rpki-repo.registro.br/rrdp/notification.xml) and searching
// // // a vector of so many deltas to withdraw the correct one will be inefficient.
// // // (maybe I should have just tried it first with a vector, too late now :-))

// // // Create a Rust "NewType" for uri::Rsync so that we can implement the required
// // // traits such that it can be used as a HashMap key. We can't implement them
// // // directly on uri::Rsync as that trait is not part of our crate.
// // // See: https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types
// // #[derive(Clone, Debug, Eq, Hash, PartialEq)]
// // struct ComparableRsyncUri(uri::Rsync);

// // type SnapshotPublishItems = HashMap<ComparableRsyncUri, Vec<u8>>;

// // impl std::fmt::Display for ComparableRsyncUri {
// //     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
// //         self.0.fmt(f)
// //     }
// // }

// // impl std::cmp::PartialOrd for ComparableRsyncUri {
// //     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
// //         Some(self.cmp(other))
// //     }
// // }

// // impl std::cmp::Ord for ComparableRsyncUri {
// //     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
// //         match self.0.module().authority().cmp(other.0.module().authority()) {
// //             std::cmp::Ordering::Less => std::cmp::Ordering::Less,
// //             std::cmp::Ordering::Equal => {
// //                 match self.0.module().module().cmp(other.0.module().module()) {
// //                     std::cmp::Ordering::Less => std::cmp::Ordering::Less,
// //                     std::cmp::Ordering::Equal => {
// //                         self.0.path().cmp(other.0.path())
// //                     },
// //                     std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
// //                 }
// //             },
// //             std::cmp::Ordering::Greater => std::cmp::Ordering::Greater
// //         }
// //     }
// // }

// // struct SnapshotParser {
// //     pub meta: Option<ParsedMeta>,
// //     pub publish: SnapshotPublishItems,
// // }

// // impl SnapshotParser {
// //     fn new() -> Self {
// //         SnapshotParser {
// //             meta: None,
// //             publish: HashMap::new(),
// //         }
// //     }
// // }

// // impl ProcessSnapshot for SnapshotParser {
// //     type Err = SnapshotParserError;

// //     fn meta(&mut self, session_id: Uuid, serial: u64) -> Result<(), Self::Err> {
// //         self.meta = Some(ParsedMeta { session_id, serial });
// //         Ok(())
// //     }

// //     fn publish(&mut self, uri: uri::Rsync, data: Vec<u8>) -> Result<(), Self::Err> {
// //         self.publish.insert(ComparableRsyncUri(uri), data);
// //         Ok(())
// //     }
// // }

// // fn parse_snapshot(buf: &[u8]) -> Result<SnapshotParser> {
// //     let cursor = std::io::Cursor::new(buf);
// //     let reader = BufReader::new(cursor);
// //     let mut processor = SnapshotParser::new();
// //     processor.process(reader).map_err(|err| {
// //         anyhow!("Error parsing snapshot XML: {:?}", &err)
// //     })?;
// //     Ok(processor)
// // }

// // // DeltaParser parses RRDP delta XML and adds/removes records to/from the
// // // referenced snapshot for publish/withdraw delta records respectively. As the
// // // DeltaParser doesn't own the snapshot it needs a mutable reference to it which
// // // is guaranteed (by 'a) to be valid as long as the DeltaParser instance exists.
// // struct DeltaParser<'a> {
// //     pub meta: Option<ParsedMeta>,
// //     pub snapshot: &'a mut SnapshotParser,
// // }

// // #[derive(Debug)]
// // enum DeltaParserError {
// //     Xml(XmlDecodeError),
// //     MismatchedSessionId(Uuid),
// //     InternalErrorMissingDeltaMeta,
// //     InternalErrorMissingSnapshotMeta,
// //     ItemToWithdrawNotFound(uri::Rsync),
// // }

// // impl From<XmlDecodeError> for DeltaParserError {
// //     fn from(err: XmlDecodeError) -> Self {
// //         DeltaParserError::Xml(err)
// //     }
// // }

// // impl<'a> DeltaParser<'a> {
// //     fn new(snapshot: &'a mut SnapshotParser) -> Self {
// //         DeltaParser {
// //             meta: None,
// //             snapshot,
// //         }
// //     }

// //     fn is_applicable(&self) -> Result<bool, DeltaParserError> {
// //         let self_meta = self.meta.as_ref().ok_or(
// //             DeltaParserError::InternalErrorMissingDeltaMeta)?;

// //         let snapshot_meta = self.snapshot.meta.as_ref().ok_or(
// //             DeltaParserError::InternalErrorMissingSnapshotMeta)?;

// //         // info!("DeltaParser::is_applicable(): delta session_id={} snapshot session_id={}", &self_meta.session_id, &snapshot_meta.session_id);
// //         // info!("DeltaParser::is_applicable(): delta serial={} snapshot serial={}", &self_meta.serial, &snapshot_meta.serial);
// //         if snapshot_meta.session_id != self_meta.session_id {
// //             Err(DeltaParserError::MismatchedSessionId(self_meta.session_id))
// //         } else {
// //             Ok(self_meta.serial > snapshot_meta.serial)
// //         }
// //     }
// // }

// // impl ProcessDelta for DeltaParser<'_> {
// //     type Err = DeltaParserError;

// //     fn meta(&mut self, session_id: Uuid, serial: u64) -> Result<(), Self::Err> {
// //         self.meta = Some(ParsedMeta { session_id, serial });
// //         Ok(())
// //     }

// //     // add the delta to the snapshot
// //     fn publish(&mut self, uri: uri::Rsync, _hash: Option<DigestHex>, data: Vec<u8>) -> Result<(), Self::Err> {
// //         if self.is_applicable()? {
// //             // add it to the snapshot, don't check if it already existed because
// //             // by URI it may already exist but just with a different value, which
// //             // it is correct that we overwrite
// //             self.snapshot.publish.insert(ComparableRsyncUri(uri), data);
// //         }
// //         Ok(())
// //     }

// //     // remove the delta from the snapshot
// //     fn withdraw(&mut self, uri: uri::Rsync, _hash: DigestHex) -> Result<(), Self::Err> {
// //         if self.is_applicable()? {
// //             // remove it from the snapshot, bail out if wasn't in the snapshot
// //             let did_not_exist = self.snapshot.publish.remove(&ComparableRsyncUri(uri.clone())).is_none();
// //             if did_not_exist {
// //                 let snapshot_meta = self.snapshot.meta.as_ref().ok_or(
// //                     DeltaParserError::InternalErrorMissingSnapshotMeta)?;
// //                 warn!("Cannot apply withdraw delta (uri={}) to snapshot (session_id={}, serial={}): no publish record by that URI exists in the snapshot",
// //                     &uri, snapshot_meta.session_id, snapshot_meta.serial);
// //                 return Err(DeltaParserError::ItemToWithdrawNotFound(uri))
// //             }
// //         } else {
// //             info!("Skipped");
// //         }
// //         Ok(())
// //     }
// // }

// // pub fn fix_uri(uri: &Https, new_authority: &str) -> Result<Https, routinator::rpki::uri::Error> {
// //     Https::from_string(uri.to_string().replace(uri.authority(), &new_authority))
// // }

// // fn parse_delta(snapshot: &mut SnapshotParser, buf: &[u8]) -> Result<()> {
// //     let cursor = std::io::Cursor::new(buf);
// //     let reader = BufReader::new(cursor);
// //     let mut processor = DeltaParser::new(snapshot);
// //     processor.process(reader).map_err(|err| {
// //         anyhow!("Error parsing snapshot XML: {:?}", &err)
// //     })?;
// //     Ok(())
// // }

// // pub fn make_delta_dir_path(
// //     notify: &NotificationFile,
// //     delta_serial: u64
// // ) -> Result<PathBuf> {
// //     let mut uiud_encode_buf = Uuid::encode_buffer();
// //     let session_id_str = notify.session_id.to_hyphenated()
// //         .encode_lower(&mut uiud_encode_buf);
// //     Ok(PathBuf::from_str(&session_id_str)?.join(delta_serial.to_string()))
// // }

// // pub fn download_raw_rrdp_notification_file(opt: &Opt, state: &State, client: &HttpClient) -> Result<Option<DownloadResult>> {
// //     info!("Downloading RRDP notification file (if supported will not re-download \
// //            if not modified)");

// //     let etag_to_use = if opt.force_update { None } else { state.notify_etag.clone() };
// //     http::download_to_buf(&opt.notification_uri, client, etag_to_use, None)
// // }

// // pub fn parse_notification_file(raw_notification_file: &[u8]) -> Result<NotificationFile> {
// //     info!("Parsing RRDP notification file");
// //     let response = std::io::Cursor::new(raw_notification_file);
// //     let mut notify = NotificationFile::parse(BufReader::new(response))?;
// //     notify.deltas.sort_unstable_by_key(|item| item.0);
// //     Ok(notify)
// // }

// // fn download_snapshot(
// //     uri: &Https,
// //     client: &HttpClient,
// //     hash: Option<DigestHex>) -> Result<Vec<u8>> {
// //     info!("Downloading RRDP snapshot file {}", &uri);
// //     let download_result = http::download_to_buf(uri, client, None, hash)
// //         .with_context(|| format!("Failed to download RRDP snapshot {}", uri))?;
// //     let body = download_result.unwrap().body;
// //     Ok(body)
// // }

// // fn apply_deltas_to_snapshot(
// //     state: &State,
// //     opt: &Opt,
// //     notify: &NotificationFile,
// //     client: &HttpClient,
// //     write_to_disk: bool) -> Result<Vec<u8>> {

// //     // Try to avoid downloading the new snapshot XML and instead construct
// //     // it from our current snapshot XML plus the impact of the new deltas.
// //     //
// //     // WARNING: this could potentially accumulate a lot of delta information
// //     // in memory at once
// //     //
// //     // 1. Load and parse our current snapshot XML from disk. It can be found
// //     //    at <rrdp output dir>/<notification file session id>/<state serial>/snapshot.xml
// //     let delta_dir = make_delta_dir_path(&notify, state.notify_serial)?;
// //     let local_snapshot_file = opt.rrdp_dir.join(delta_dir).join(config::SNAPSHOT_FNAME);

// //     if !local_snapshot_file.is_file() {
// //         warn!("Couldn't find RRDP snapshot file {:?}, will re-download it.", local_snapshot_file);
// //         Err(anyhow!("Missing RRDP snapshot file"))
// //     } else {
// //         info!("Applying RRDP deltas to last RRDP snapshot");
// //         let mut parsed_snapshot = {
// //             let buf = file_ops::read_file(&local_snapshot_file)?;
// //             parse_snapshot(buf.as_slice())?
// //         };

// //         // 2. Apply the new deltas from the notification file to the
// //         // loaded snapshot. This is very similar to but we can't quite
// //         // use the routinator::rrdp::server::delta_update() as
// //         // Routinator updates its Rsync like repo on disk and doesn't
// //         // use it to generate an updated XML snapshot.
// //         let mut current_serial = state.notify_serial;

// //         // identify required deltas
// //         let deltas_to_apply: Vec<_> = notify.deltas.iter().filter_map(|(serial, uri_and_hash)| {
// //             match *serial {
// //                 s if s <= current_serial => {
// //                     // old delta, already incorporated into our snapshot
// //                     // so ignore
// //                     None
// //                 },
// //                 s if s == current_serial + 1 => {
// //                     let delta_dir_path = make_delta_dir_path(&notify, *serial).unwrap();
// //                     let delta_dir_path = opt.rrdp_dir.join(delta_dir_path);
// //                     let delta_file_path = delta_dir_path.join(config::DELTA_FNAME);
// //                     let uri = fix_uri(uri_and_hash.uri(), opt.notification_uri.authority()).unwrap();
// //                     let hash = uri_and_hash.hash();
// //                     current_serial += 1;
// //                     Some((serial, uri, hash, delta_file_path))
// //                 },
// //                 _ => {
// //                     panic!("Internal error: unexpected delta serial {}, aborting.", serial);
// //                 },
// //             }
// //         }).collect();

// //         // identify missing deltas
// //         let deltas_to_download: Vec<DownloadType> = deltas_to_apply.iter().filter_map(|(_, uri, hash, path)| {
// //             if !path.is_file() {
// //                 #[allow(clippy::match_bool)]
// //                 Some(match write_to_disk {
// //                     true  => DownloadType::ToFile((uri.clone(), Some(*hash).cloned(), path.clone())),
// //                     false => DownloadType::ToBuf(uri.clone(), Some(*hash).cloned()),
// //                 })
// //             } else {
// //                 None
// //             }
// //         }).collect();

// //         // download missing deltas, either to disk if a local RRDP repository
// //         // should be written out, or hold them in memory otherwise to apply to
// //         // the snapshot in the correct order
// //         let downloaded_deltas = http::download_multiple(&deltas_to_download, &client)?;

// //         // apply the required deltas to the snapshot in the correct order
// //         for (serial, uri, _, path) in deltas_to_apply {
// //             let buf = if let Some((_, dl_result)) = downloaded_deltas.remove(&uri) {
// //                 match dl_result {
// //                     http::MultiDownloadResult::ToBuf(buf) => buf.to_vec(),
// //                     http::MultiDownloadResult::ToFile(path) => {
// //                         file_ops::read_file(path.as_path())?
// //                     }
// //                 }
// //             } else {
// //                 file_ops::read_file(path.as_path())?
// //             };

// //             // // check the buffer contents match the hash
// //             // if hash.as_ref() != calc_hash(&buf).as_ref() {
// //             //     error!("RRDP delta {} hash mismatch, aborting", serial);
// //             //     return Err(anyhow!("RRDP delta {} hash mismatch, aborting", serial));
// //             // }

// //             debug!("Applying RRDP delta {} to snapshot", serial);
// //             parse_delta(&mut parsed_snapshot, buf.as_slice())?;
// //         }

// //         // generate an in-memory representation of the new snapshot XML
// //         // note: it's important that this is generated consistently on
// //         // different servers in a cluster each running krill-sync against
// //         // the remote RRDP server, so that clients load balanced to
// //         // different krill-sync nodes in the cluster receive a notification
// //         // file whose snapshot hash matches the hash calculated for the
// //         // received snapshot file.
// //         let mut new_snapshot = String::new();
// //         new_snapshot.push_str(
// //             &format!(
// //                 r#"<snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id="{}" serial="{}">{}"#,
// //                 &notify.session_id,
// //                 &notify.serial,
// //                 "\n"));

// //         for (uri, data) in parsed_snapshot.publish.iter() {
// //             new_snapshot.push_str(
// //                 &format!(
// //                     r#"  <publish uri="{}">{}</publish>{}"#,
// //                     uri,
// //                     base64::encode(data),
// //                     "\n"));
// //         }

// //         new_snapshot.push_str("</snapshot>");

// //         if !new_snapshot.is_ascii() {
// //             panic!("Generated snapshot violates RFC-8182 because it contains non-ascii characters, aborting.");
// //         }

// //         let mut buf = Vec::new();
// //         buf.extend(new_snapshot.bytes());
// //         Ok(buf)
// //     }
// // }

// // pub fn get_snapshot(
// //     state_loaded: bool,
// //     state: &State,
// //     opt: &Opt,
// //     notify: &mut NotificationFile,
// //     client: &HttpClient,
// //     write_to_disk: bool) -> Result<(Vec<u8>, bool)> {
// //     // Note: According to https://tools.ietf.org/html/rfc8182#section-3.3.1
// //     // the initial serial number MUST be 1, so State::notify_serial defaults
// //     // to 0 when no state or prior snapshot is available.
// //     if state_loaded && state.notify_serial >= 1 && !opt.force_snapshot {
// //         let updated_raw_snapshot = apply_deltas_to_snapshot(state, opt, notify, client, write_to_disk);
// //         if let Ok(body) = updated_raw_snapshot {
// //             return Ok((body, true));
// //         }
// //     }

// //     let downloaded_snapshot = download_snapshot(
// //         notify.snapshot.uri(), client, Some(notify.snapshot.hash()).cloned())?;
// //     Ok((downloaded_snapshot, false))
// // }

// // pub fn update_notification_hash(
// //     raw_notification_file: Vec<u8>,
// //     notify: &mut NotificationFile,
// //     new_hash: DigestHex) -> Result<Vec<u8>>
// // {
// //     let raw_notification_file = String::from_utf8(raw_notification_file)?.replace(
// //         &notify.snapshot.hash().to_string(), &new_hash.to_string()).into_bytes();

// //     // Update our in-memory metadata about the notification file to
// //     // match the changes we have made
// //     notify.snapshot = UriAndHash::new(notify.snapshot.uri().clone(), new_hash);
// //     Ok(raw_notification_file)
// // }

// // pub fn calc_hash(snapshot: &[u8]) -> DigestHex {
// //     DigestHex::from(digest::digest(&digest::SHA256, &snapshot))
// // }

// // pub fn download_deltas(
// //     opt: &Opt,
// //     notify: &mut NotificationFile,
// //     client: &HttpClient) -> Result<()>
// // {
// //     let num_deltas = notify.deltas.len();
// //     if num_deltas > 0 {
// //         info!("Checking for missing RRDP delta files");
// //         let deltas_to_download: Vec<_> = notify.deltas.iter().filter_map(|(serial, uri_and_hash)| {
// //             let delta_dir_path = make_delta_dir_path(&notify, *serial).unwrap();
// //             let delta_dir_path = opt.rrdp_dir.join(delta_dir_path);
// //             let delta_file_path = delta_dir_path.join(config::DELTA_FNAME);
// //             if !delta_file_path.is_file() {
// //                 let fixed_uri = fix_uri(uri_and_hash.uri(), opt.notification_uri.authority()).unwrap();
// //                 Some(DownloadType::ToFile((fixed_uri, Some(uri_and_hash.hash()).cloned(), delta_file_path)))
// //             } else {
// //                 None
// //             }
// //         }).collect();

// //         http::download_multiple(&deltas_to_download, client)?;
// //     }

// //     Ok(())
// // }
