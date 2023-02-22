use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rpki::{
    repository::{
        aspa::Aspa, error::VerificationError, x509::Time, Cert, Crl, Manifest, ResourceCert, Roa,
    },
    rrdp::{NotificationFile, Snapshot, UriAndHash},
    uri,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::fetch::{FetchMode, Fetcher, NotificationFileResponse};

use super::{
    IgnoredObjectInfo, Tal, ValidatedAspa, ValidatedCaCertInfo, ValidatedCaCertificate,
    ValidatedChild, ValidatedRoa, ValidatedRouterCert, ValidationIssue, ValidationReport,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct Validator {
    tals: Vec<Tal>,
    repositories: VisitedRepositories,
}

impl Validator {
    pub fn new(tals: Vec<Tal>, fetchers: Vec<Fetcher>) -> Self {
        Validator {
            tals,
            repositories: VisitedRepositories {
                fetchers: Mutex::new(
                    fetchers
                        .into_iter()
                        .map(|fetcher| (fetcher.notification_uri().clone(), Arc::new(fetcher)))
                        .collect(),
                ),
                data: Mutex::new(HashMap::new()),
            },
        }
    }

    /// Checks whether this Validator includes the same TALs and
    /// has at least all fetchers included in the other validator.
    ///
    /// If so, then this Validator can be considered an equivalent,
    /// existing, instance that should be used. Note that this Validator
    /// is not *equal* because it may include other repository fetchers
    /// and it would have downloaded repository data.
    pub fn equivalent(&self, other: &Validator) -> bool {
        let self_repositories = self.repositories.fetchers.lock().unwrap();
        let other_repositories = other.repositories.fetchers.lock().unwrap();

        for other_repo in other_repositories.values() {
            if !self_repositories
                .values()
                .any(|self_repo| self_repo == other_repo)
            {
                return false;
            }
        }

        self.tals == other.tals
    }

    pub fn validate(&self, local: Option<&LocalNotificationFile>) -> Result<ValidationReport> {
        self.validate_at(local, Time::now())
    }

    pub fn validate_at(
        &self,
        local: Option<&LocalNotificationFile>,
        when: Time,
    ) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        for tal in &self.tals {
            report.add_other(self.validate_ta_at(tal, local, when)?);
        }

        Ok(report)
    }

    pub fn validate_ta_at(
        &self,
        tal: &Tal,
        local: Option<&LocalNotificationFile>,
        when: Time,
    ) -> Result<ValidationReport> {
        let ta_cert = tal.validate_at(when)?;

        let info = ValidatedCaCertInfo::try_from(&ta_cert)
            .map_err(|e| anyhow!(format!("Invalid TA certificate: {e}")))?;

        Ok(self.validate_tree_at(&ta_cert, &info, local, when))
    }

    fn validate_tree_at(
        &self,
        resource_cert: &ResourceCert,
        ca_cert_info: &ValidatedCaCertInfo,
        local: Option<&LocalNotificationFile>,
        when: Time,
    ) -> ValidationReport {
        let mut report = ValidationReport::default();
        let mut ca_cert = ValidatedCaCertificate::empty(ca_cert_info.clone());

        let mut child_certificates = vec![];

        {
            let mft_uri = &ca_cert_info.sia_mft;
            let sia_ca = &ca_cert_info.sia_ca;

            let sia_rrdp = match &ca_cert.ca_cert_info.sia_rrdp {
                Some(uri) => uri,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        sia_ca.clone(),
                        "No SIA RRDP entry",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let data = match self.repositories.update(sia_rrdp, local) {
                Ok(data) => data,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        sia_ca.clone(),
                        format!("Could not get repo data from {sia_rrdp}: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let mft_obj = match data.objects.get(mft_uri) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        "No manifest found",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let mft = match Manifest::decode(mft_obj.bytes().clone(), true) {
                Ok(mft) => mft,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        format!("Cannot parse manifest: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let (mft_cert, content) = match mft.validate_at(resource_cert, true, when) {
                Ok((mft_cert, content)) => (mft_cert, content),
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        format!("Invalid manifest: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            #[allow(clippy::mutable_key_type)]
            let mut mft_entries: HashMap<_, _> = content.iter_uris(sia_ca).collect();

            let crl_uri = match mft_cert.crl_uri() {
                Some(uri) => uri,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        "Manifest EE has no CRL uri",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let crl_hash = match mft_entries.remove(crl_uri) {
                Some(hash) => hash,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        format!("CRL with uri {crl_uri} is not on manifest"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let crl_obj = match data.objects.get(crl_uri) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        crl_uri.clone(),
                        format!("CRL at {crl_uri} not found"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            if crl_hash.verify(crl_obj.bytes()).is_err() {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri.clone(),
                    "CRL does not match hash on manifest",
                ));
                report.add_cert(ca_cert);
                return report;
            };

            let crl = match Crl::decode(crl_obj.bytes().clone()) {
                Ok(crl) => crl,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        crl_uri.clone(),
                        format!("Could not parse CRL: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            if crl
                .verify_signature(resource_cert.subject_public_key_info())
                .is_err()
            {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri.clone(),
                    "CRL not validly signed",
                ));
                report.add_cert(ca_cert);
                return report;
            };

            if crl.next_update() < when {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri.clone(),
                    "CRL is stale",
                ));
                report.add_cert(ca_cert);
                return report;
            }

            if crl.contains(mft_cert.serial_number()) {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    mft_uri.clone(),
                    "Manifest was revoked",
                ));
                report.add_cert(ca_cert);
                return report;
            }

            // Ok.. the CRL and Manifest are okay..
            //
            // We need at least a valid Manifest and CRL to validate
            // objects on the manifest. But we can now validate each
            // of those objects individually and just report issues
            // if applicable, but continue with the next object.
            for (uri, hash) in mft_entries.into_iter() {
                let object = match data.objects.get(&uri) {
                    Some(object) => object,
                    None => {
                        ca_cert
                            .add_issue(ValidationIssue::with_uri_and_msg(uri, "Object not found"));
                        continue;
                    }
                };

                if hash.verify(object.bytes()).is_err() {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        uri,
                        "Object does not match manifest hash",
                    ));
                    continue;
                };

                let path = uri.path();
                let extension = if path.len() > 4 {
                    &path[path.len() - 3..]
                } else {
                    ""
                };

                match extension {
                    "roa" => match Roa::decode(object.bytes().clone(), true) {
                        Ok(roa) => match roa.process(resource_cert, true, |roa_cert| {
                            if crl.contains(roa_cert.serial_number()) {
                                Err(VerificationError::new(format!("ROA at {uri} was revoked"))
                                    .into())
                            } else {
                                Ok(())
                            }
                        }) {
                            Ok((_roa_cert, roa)) => {
                                let roa = ValidatedRoa::make(uri, roa);
                                ca_cert.add_roa(roa);
                            }
                            Err(e) => {
                                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                    uri,
                                    format!("Invalid ROA: {e}"),
                                ));
                            }
                        },
                        Err(e) => {
                            ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                uri,
                                format!("Cannot decode ROA: {e}"),
                            ));
                        }
                    },
                    "cer" => {
                        match Cert::decode(object.bytes().clone()) {
                            Ok(child_cert) => {
                                if child_cert.is_ca() {
                                    // This could be a CA certificate delegated to a child
                                    if crl.contains(child_cert.serial_number()) {
                                        ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                            uri,
                                            "certificate was revoked",
                                        ));
                                    } else {
                                        match child_cert.validate_ca_at(resource_cert, true, when) {
                                            Ok(child_resource_cert) => {
                                                match ValidatedCaCertInfo::try_from(
                                                    &child_resource_cert,
                                                ) {
                                                    Ok(cert_info) => {
                                                        ca_cert.add_child(ValidatedChild::new(
                                                            uri,
                                                            cert_info.clone(),
                                                        ));
                                                        child_certificates
                                                            .push((child_resource_cert, cert_info));
                                                    }
                                                    Err(e) => {
                                                        ca_cert.add_issue(
                                                            ValidationIssue::with_uri_and_msg(
                                                                uri,
                                                                format!(
                                                                    "certificate was invalid: {e}"
                                                                ),
                                                            ),
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                ca_cert.add_issue(
                                                    ValidationIssue::with_uri_and_msg(
                                                        uri,
                                                        format!("certificate was invalid: {e}"),
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    // This should be a BGPSec router (EE) certificate
                                    match child_cert.validate_router_at(resource_cert, true, when) {
                                        Ok(_) => {
                                            ca_cert.add_router_cert(ValidatedRouterCert::new(uri))
                                        }
                                        Err(e) => {
                                            ca_cert.add_issue(
                                                ValidationIssue::with_uri_and_msg(
                                                    uri,
                                                    format!("EE certificate found, but it is an invalid router certificate: {e}")
                                                )
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                    uri,
                                    format!("Cannot parse child certificate: {e}"),
                                ));
                            }
                        };
                    }
                    "asa" => match Aspa::decode(object.bytes().clone(), true) {
                        Ok(aspa) => match aspa.process(resource_cert, true, |ee| {
                            if crl.contains(ee.serial_number()) {
                                Err(VerificationError::new(format!("ROA at {uri} was revoked"))
                                    .into())
                            } else {
                                Ok(())
                            }
                        }) {
                            Ok((_ee, aspa)) => {
                                ca_cert.add_aspa(ValidatedAspa::make(uri, aspa));
                            }
                            Err(e) => {
                                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                    uri,
                                    format!("Invalid ASPA: {e}"),
                                ));
                            }
                        },
                        Err(e) => {
                            ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                                uri,
                                format!("Cannot parse aspa object: {e}"),
                            ));
                        }
                    },
                    "gbr" => ca_cert.add_ignored(IgnoredObjectInfo::new(
                        uri,
                        "Ghostbuster records are not yet validated.",
                    )),
                    _ => {
                        // note.. we borrowed extension from uri so we can only use it to
                        // format before moving uri.
                        let msg = format!("unsupported object type: {extension}");
                        ca_cert.add_issue(ValidationIssue::with_uri_and_msg(uri, msg));
                    }
                }
            }
        }

        // Add the results for this CA certificate validation.
        report.add_cert(ca_cert);

        // recurse child certificates
        for (cert, info) in child_certificates {
            report.add_other(self.validate_tree_at(&cert, &info, local, when));
        }

        report
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VisitedRepositories {
    fetchers: Mutex<HashMap<uri::Https, Arc<Fetcher>>>,
    data: Mutex<HashMap<uri::Https, Arc<RepositoryData>>>,
}

#[derive(Clone, Debug)]
pub struct LocalNotificationFile {
    pub uri: uri::Https,
    pub notification: NotificationFile,
}

impl VisitedRepositories {
    fn update(
        &self,
        notify_uri: &uri::Https,
        local: Option<&LocalNotificationFile>,
    ) -> Result<Arc<RepositoryData>> {
        if !self.has_repository(notify_uri) {
            self.retrieve_new_repository(notify_uri, local)?;
        } else {
            self.update_existing_repository(notify_uri, local)?;
        }

        let data = self.data.lock().unwrap();
        data.get(notify_uri)
            .cloned()
            .ok_or(anyhow!("No data for repository at: {}", notify_uri))
    }

    fn has_repository(&self, notify_uri: &uri::Https) -> bool {
        let data = self.data.lock().unwrap();
        data.contains_key(notify_uri)
    }

    fn update_existing_repository(
        &self,
        notify_uri: &uri::Https,
        local: Option<&LocalNotificationFile>,
    ) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        let fetcher = self.get_fetcher(notify_uri)?;

        let repo_data = data
            .get_mut(notify_uri)
            .ok_or_else(|| anyhow!("No existing data for {}", notify_uri))?;

        match self.read_notification_file(&fetcher, notify_uri, local, repo_data.etag.as_ref())? {
            NotificationFileResponse::Unmodified => Ok(()),
            NotificationFileResponse::Data { notification, etag } => {
                // TODO: get from deltas
                let repo_data = Self::repository_data_from_snapshot(notification, etag, &fetcher)?;
                data.insert(notify_uri.clone(), Arc::new(repo_data));

                Ok(())
            }
        }
    }

    fn retrieve_new_repository(
        &self,
        notify_uri: &uri::Https,
        local: Option<&LocalNotificationFile>,
    ) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        let fetcher = self.get_fetcher(notify_uri)?;

        let (notification, etag) = self
            .read_notification_file(&fetcher, notify_uri, local, None)?
            .content()?;

        let repo_data = Self::repository_data_from_snapshot(notification, etag, &fetcher)?;

        data.insert(notify_uri.clone(), Arc::new(repo_data));
        Ok(())
    }

    fn repository_data_from_snapshot(
        notification: NotificationFile,
        etag: Option<String>,
        fetcher: &Fetcher,
    ) -> Result<RepositoryData> {
        let serial = notification.serial();
        let session_id = notification.session_id();

        let snapshot_uri_hash = notification.snapshot();
        let snapshot = Self::read_snapshot_file(&fetcher, snapshot_uri_hash)?;

        #[allow(clippy::mutable_key_type)]
        let objects: HashMap<uri::Rsync, RepositoryObject> = snapshot
            .into_elements()
            .into_iter()
            .map(|e| {
                let (uri, bytes) = e.unpack();
                (uri, RepositoryObject { bytes })
            })
            .collect();

        Ok(RepositoryData {
            etag,
            session_id,
            serial,
            objects,
        })
    }

    fn read_notification_file(
        &self,
        fetcher: &Fetcher,
        notify_uri: &uri::Https,
        local: Option<&LocalNotificationFile>,
        etag: Option<&String>,
    ) -> Result<NotificationFileResponse> {
        if let Some(local) = local {
            if &local.uri == notify_uri {
                Ok(NotificationFileResponse::Data {
                    etag: None,
                    notification: local.notification.clone(),
                })
            } else {
                fetcher.read_notification_file(etag)
            }
        } else {
            fetcher.read_notification_file(etag)
        }
    }

    fn read_snapshot_file(fetcher: &Fetcher, snapshot_uri_hash: &UriAndHash) -> Result<Snapshot> {
        let snapshot_source = fetcher.resolve_source(snapshot_uri_hash.uri())?;
        let snapshot_data = snapshot_source
            .fetch(Some(snapshot_uri_hash.hash()), None, None)?
            .try_into_data()?;

        Snapshot::parse(snapshot_data.as_ref())
            .with_context(|| format!("Cannot parse snapshot at uri: {}", snapshot_uri_hash.uri()))
    }

    fn get_fetcher(&self, notify_uri: &uri::Https) -> Result<Arc<Fetcher>> {
        let mut fetchers = self.fetchers.lock().unwrap();

        if !fetchers.contains_key(notify_uri) {
            let fetcher = Fetcher::new(notify_uri.clone(), None, FetchMode::Insecure);
            fetchers.insert(notify_uri.clone(), Arc::new(fetcher));
        }

        fetchers
            .get(notify_uri)
            .cloned()
            .ok_or(anyhow!("No fetcher for repository at: {}", notify_uri))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryData {
    // todo: Track session and serial so we can apply deltas
    //       rather than getting the full snapshot.
    //       This only becomes relevant when we start using this from
    //       a daemon and/or persist this data between sync sessions.
    etag: Option<String>,
    session_id: Uuid,
    serial: u64,
    objects: HashMap<uri::Rsync, RepositoryObject>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryObject {
    #[serde(serialize_with = "ser_bytes", deserialize_with = "de_bytes")]
    bytes: Bytes,
}

impl RepositoryObject {
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

pub fn de_bytes<'de, D>(d: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let some = String::deserialize(d)?;
    let dec = base64::decode(some).map_err(de::Error::custom)?;
    Ok(Bytes::from(dec))
}

pub fn ser_bytes<S>(b: &Bytes, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64::encode(b).serialize(s)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use bytes::Bytes;

    use crate::fetch::{FetchMap, FetchSource};

    use super::*;

    #[test]
    fn top_down_validation() {
        let tal_bytes = include_bytes!("../../test-resources/validation/good/ta.tal");
        let tal_bytes = Bytes::from_static(tal_bytes);
        let source = FetchSource::File(PathBuf::from("test-resources/validation/good/ta.cer"));

        let tal = Tal::parse("tal".to_string(), tal_bytes, Some(source)).unwrap();

        let notification_uri =
            uri::Https::from_str("https://localhost:3000/rrdp/notification.xml").unwrap();

        let fetch_map = FetchMap::new(
            uri::Https::from_str("https://localhost:3000/rrdp/").unwrap(),
            FetchSource::File(PathBuf::from("test-resources/validation/good/rrdp/")),
        );
        let fetcher = Fetcher::new(notification_uri, Some(fetch_map), FetchMode::Insecure);

        let validator = Validator::new(vec![tal], vec![fetcher]);

        validator
            .validate_at(None, Time::utc(2023, 2, 13, 15, 58, 00))
            .unwrap();
    }
}
