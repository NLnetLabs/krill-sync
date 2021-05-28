use rpki::rrdp::{Delta, NotificationFile, Snapshot};

// use std::convert::TryFrom;
// use std::convert::TryInto;
// use std::io;
// use std::io::Read;
// use std::fmt;

// use bytes::Bytes;
// use uuid::Uuid;

// use rpki::{
//     rrdp::{NotificationFile, ObjectReader, ProcessError, ProcessSnapshot},
//     uri,
// };

// use rpki::xml::decode::Error as XmlError;

pub struct RrdpState {
    notification: NotificationFile,
    snapshot: Snapshot,
    deltas: Vec<Delta>
}

impl RrdpState {
    pub fn new(
        notification: NotificationFile,
        snapshot: Snapshot,
        deltas: Vec<Delta>
    ) -> Self {
        RrdpState { notification, snapshot, deltas }
    }

    pub fn notification(&self) -> &NotificationFile {
        &self.notification
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
}

// pub struct PublishElement {
//     uri: uri::Rsync,
//     data: Bytes,
// }

// pub struct Snapshot {
//     session_id: Uuid,
//     serial: u64,
//     elements: Vec<PublishElement>,
// }

// impl Snapshot {
//     /// Parse 
//     pub fn parse<R: io::BufRead>(
//         reader: R
//     ) -> Result<Self, RrdpProcessError> {
//         let mut builder = SnapshotBuilder {
//             session_id: None,
//             serial: None,
//             elements: vec![]
//         };

//         builder.process(reader)?;
//         builder.try_into()
//     }
// }

// struct SnapshotBuilder {
//     session_id: Option<Uuid>,
//     serial: Option<u64>,
//     elements: Vec<PublishElement>,
// }


// impl ProcessSnapshot for SnapshotBuilder {
//     type Err = RrdpProcessError;

//     fn meta(&mut self, session_id: Uuid, serial: u64) -> Result<(), Self::Err> {
//         self.session_id = Some(session_id);
//         self.serial = Some(serial);
//         Ok(())
//     }

//     fn publish(&mut self, uri: uri::Rsync, data: &mut ObjectReader) -> Result<(), Self::Err> {
//         let mut buf = Vec::new();
//         data.read_to_end(&mut buf)?;
//         let data = Bytes::from(buf);
//         let element = PublishElement { uri, data };
//         self.elements.push(element);
//         Ok(())
//     }
// }

// impl TryFrom<SnapshotBuilder> for Snapshot {
//     type Error = RrdpProcessError;

//     fn try_from(builder: SnapshotBuilder) -> Result<Self, Self::Error> {
//         let session_id = builder.session_id.ok_or_else(||
//             RrdpProcessError::Xml(XmlError::Malformed)
//         )?;

//         let serial = builder.serial.ok_or_else(||
//             RrdpProcessError::Xml(XmlError::Malformed)
//         )?;

//         Ok(Snapshot { session_id, serial, elements: builder.elements })
//     }
// }
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
