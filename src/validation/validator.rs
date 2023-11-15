use core::fmt;
use std::{collections::HashMap, convert::TryFrom, sync::Arc};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use chrono::Duration;
use log::{debug, info, trace, warn};
use rpki::{
    repository::{
        aspa::Aspa, error::VerificationError, x509::Time, Cert, Crl, Manifest, ResourceCert, Roa,
    },
    rrdp::{self, Delta, DeltaElement, NotificationFile, Snapshot},
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
                fetchers: fetchers
                    .into_iter()
                    .map(|fetcher| (fetcher.notification_uri().clone(), Arc::new(fetcher)))
                    .collect(),
                data: HashMap::new(),
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
        let self_repositories = &self.repositories.fetchers;
        let other_repositories = &other.repositories.fetchers;

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

    /// Ensure that the staged data is updated even if we are
    /// running in offline mode.
    pub fn initialise_staging_data(&mut self, notify_uri: &uri::Https) -> Result<()> {
        self.repositories
            .get_latest(notify_uri, false, Time::now())?;
        Ok(())
    }

    pub fn validate(&mut self, offline: bool) -> Result<ValidationReport> {
        self.validate_at(offline, Time::now())
    }

    pub fn validate_at(&mut self, offline: bool, when: Time) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        for tal in self.tals.clone() {
            info!("Validate TA {}", tal.name());
            report.add_other(self.validate_ta_at(&tal, offline, when)?);
        }

        Ok(report)
    }

    pub fn validate_ta_at(
        &mut self,
        tal: &Tal,
        offline: bool,
        when: Time,
    ) -> Result<ValidationReport> {
        let ta_cert = tal.validate_at(when)?;

        let info = ValidatedCaCertInfo::try_from(&ta_cert)
            .map_err(|e| anyhow!(format!("Invalid TA certificate: {e}")))?;

        Ok(self.validate_tree_at(&ta_cert, &info, offline, when))
    }

    fn validate_tree_at(
        &mut self,
        resource_cert: &ResourceCert,
        ca_cert_info: &ValidatedCaCertInfo,
        offline: bool,
        when: Time,
    ) -> ValidationReport {
        trace!(
            "Validate CA with SIA: {} and RRDP: {}",
            ca_cert_info.sia_ca,
            ca_cert_info
                .sia_rrdp
                .as_ref()
                .map(|uri| uri.as_str())
                .unwrap_or("<none>")
        );

        let strict = false; // todo.. take this from config

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
                        sia_ca.into(),
                        "No SIA RRDP entry",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let data = match self.repositories.get_latest(sia_rrdp, offline, when) {
                Ok(data) => data,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        sia_ca.into(),
                        format!("Could not get repo data from {sia_rrdp}: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let mft_uri_string = UriString::from(mft_uri);
            let mft_obj = match data.objects.get(&mft_uri_string) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri_string,
                        "No manifest found",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let mft = match Manifest::decode(mft_obj.bytes().clone(), strict) {
                Ok(mft) => mft,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri_string,
                        format!("Cannot parse manifest: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let (mft_cert, content) = match mft.validate_at(resource_cert, strict, when) {
                Ok((mft_cert, content)) => (mft_cert, content),
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri_string,
                        format!("Invalid manifest: {e}"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            #[allow(clippy::mutable_key_type)]
            let mut mft_entries: HashMap<_, _> = content
                .iter_uris(sia_ca)
                .map(|(k, v)| (UriString::from(k), v))
                .collect();

            let crl_uri = match mft_cert.crl_uri() {
                Some(uri) => UriString::from(uri),
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri_string,
                        "Manifest EE has no CRL uri",
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let crl_hash = match mft_entries.remove(&crl_uri) {
                Some(hash) => hash,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri_string,
                        format!("CRL with uri {crl_uri} is not on manifest"),
                    ));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            let crl_obj = match data.objects.get(&crl_uri) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(crl_uri, "CRL not found"));
                    report.add_cert(ca_cert);
                    return report;
                }
            };

            if crl_hash.verify(crl_obj.bytes()).is_err() {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri,
                    "CRL does not match hash on manifest",
                ));
                report.add_cert(ca_cert);
                return report;
            };

            let crl = match Crl::decode(crl_obj.bytes().clone()) {
                Ok(crl) => crl,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        crl_uri,
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
                    crl_uri,
                    "CRL not validly signed",
                ));
                report.add_cert(ca_cert);
                return report;
            };

            if crl.next_update() < when {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(crl_uri, "CRL is stale"));
                report.add_cert(ca_cert);
                return report;
            }

            if crl.contains(mft_cert.serial_number()) {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri,
                    "Manifest was revoked",
                ));
                report.add_cert(ca_cert);
                return report;
            }

            trace!("will validate {} manifest entries", mft_entries.len());

            // Ok.. the CRL and Manifest are okay..
            //
            // We need at least a valid Manifest and CRL to validate
            // objects on the manifest. But we can now validate each
            // of those objects individually and just report issues
            // if applicable, but continue with the next object.
            let mut validated = 0;
            for (uri, hash) in mft_entries.into_iter() {
                if validated > 1 && validated % 50 == 0 {
                    trace!("   -- validated {validated} items");
                }

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

                match uri.extension() {
                    "roa" => match Roa::decode(object.bytes().clone(), strict) {
                        Ok(roa) => match roa.process(resource_cert, strict, |roa_cert| {
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
                                        match child_cert.validate_ca_at(resource_cert, strict, when)
                                        {
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
                                    match child_cert.validate_router_at(resource_cert, strict, when)
                                    {
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
                    "asa" => match Aspa::decode(object.bytes().clone(), strict) {
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
                        let msg = format!("unsupported object type: {}", uri.extension());
                        ca_cert.add_issue(ValidationIssue::with_uri_and_msg(uri, msg));
                    }
                }

                validated += 1;
            }
        }

        // Add the results for this CA certificate validation.
        report.add_cert(ca_cert);

        // recurse child certificates
        for (cert, info) in child_certificates {
            report.add_other(self.validate_tree_at(&cert, &info, offline, when));
        }

        report
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VisitedRepositories {
    fetchers: HashMap<uri::Https, Arc<Fetcher>>,
    data: HashMap<UriString, RepositoryData>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UriString(String);

impl UriString {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    pub fn extension(&self) -> &str {
        match self.as_str().rsplit_once('.') {
            None => "",
            Some((_left, extension)) => extension,
        }
    }
}

impl AsRef<str> for UriString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&uri::Https> for UriString {
    fn from(uri: &uri::Https) -> Self {
        UriString(uri.to_string())
    }
}

impl From<uri::Https> for UriString {
    fn from(uri: uri::Https) -> Self {
        UriString(uri.to_string())
    }
}

impl From<&uri::Rsync> for UriString {
    fn from(uri: &uri::Rsync) -> Self {
        UriString(uri.to_string())
    }
}

impl From<uri::Rsync> for UriString {
    fn from(uri: uri::Rsync) -> Self {
        UriString(uri.to_string())
    }
}

impl fmt::Display for UriString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl VisitedRepositories {
    /// Gets the latest data for the given notify_uri.
    ///
    /// Will update local data if needed, or return existing data if
    /// no update was needed.
    fn get_latest(
        &mut self,
        notify_uri: &uri::Https,
        offline: bool,
        when: Time,
    ) -> Result<&RepositoryData> {
        let fetcher = self.get_fetcher(notify_uri);
        let notify_uri_string = UriString::from(notify_uri);

        match self.data.get_mut(&notify_uri_string) {
            None => {
                if offline {
                    debug!("Skip downloading content for {notify_uri} in offline validation mode.")
                } else {
                    // We did not have any data for this notify_uri, so add
                    // it now as a new repository.
                    debug!("New repository found. Will sync data for {notify_uri}");
                    match Self::retrieve_new_repository(&fetcher, when) {
                        Ok(repo_data) => {
                            debug!("Save repository data for {notify_uri}");
                            self.data.insert(notify_uri_string, repo_data);
                        }
                        Err(e) => {
                            warn!("Could not update repository for {notify_uri}. Error: {e}");
                            return Err(e);
                        }
                    }
                }
            }
            Some(repo_data) => {
                // Ensure we don't try to fetch the same notify.xml if we
                // already updated it in this run, or within the last 5 minutes.
                //
                // TODO: make this time configurable.

                if repo_data.fetched {
                    // nothing to fetch.. don't even trace log
                } else if offline {
                    debug!("Use cached data for {notify_uri} in offline validation mode.");
                    repo_data.fetched = true;
                } else if repo_data.last_fetch > Time::now() - Duration::minutes(60) {
                    debug!("Won't check {notify_uri} in this run. It was updated recently.");
                    repo_data.fetched = true;
                } else {
                    // Mark repo as fetched. We should only try once per run.
                    //
                    // Marking it here as fetched ensures that it we don't try again, even
                    // if fetching the notification file fails.
                    repo_data.fetched = true;

                    // Get the notification response to see if we need
                    // to update the data.
                    let notification_response =
                        fetcher.read_notification_file(repo_data.etag.as_ref())?;

                    match notification_response {
                        NotificationFileResponse::Unmodified => {
                            // Nothing to update, proceed.
                        }
                        NotificationFileResponse::Data { notification, etag } => {
                            // New notification file retrieved, or well... etag may not
                            // have been supported, so check the session_id and serial
                            // to be sure..
                            if notification.session_id() == repo_data.session_id
                                && notification.serial() == repo_data.serial
                            {
                                trace!("Notification file at uri {notify_uri} is unchanged (but does not support etag)");
                            } else {
                                debug!("Notification file at uri {notify_uri} was updated, will try to apply deltas");
                                // Try to apply deltas. If this fails, then try to apply
                                // the snapshot. If that also fails, then just remove the
                                // data for this repository as we can't get the current
                                // content. Note that this would point at a serious issue
                                // with the publication server in question because it
                                // would mean that it gave us a correct notification file,
                                // but can't give the correct snapshot on that file.
                                if let Err(e) = Self::update_repository_data_from_deltas(
                                    notification.clone(),
                                    etag.clone(),
                                    repo_data,
                                    &fetcher,
                                    when,
                                ) {
                                    debug!("Could not apply delta for {notify_uri}, will try snapshot. Reason: {e}");
                                    match Self::repository_data_from_snapshot(
                                        notification,
                                        etag,
                                        &fetcher,
                                        when,
                                    ) {
                                        Ok(repo_data) => {
                                            debug!(
                                                "Data for {notify_uri} was updated using snapshot"
                                            );
                                            self.data.insert(notify_uri_string, repo_data);
                                        }
                                        Err(e) => {
                                            debug!("Could not apply snapshot for {notify_uri}, will remove content. Reason: {e}");
                                            self.data.remove(&notify_uri_string);
                                        }
                                    }
                                } else {
                                    debug!("Data for uri {notify_uri} was updated using deltas");
                                }
                            }
                        }
                    }
                }
            }
        }

        self.data
            .get(&notify_uri.into())
            .ok_or(anyhow!("No data for repository at: {}", notify_uri))
    }

    fn retrieve_new_repository(fetcher: &Fetcher, when: Time) -> Result<RepositoryData> {
        let (notification, etag) = fetcher.read_notification_file(None)?.content()?;
        Self::repository_data_from_snapshot(notification, etag, fetcher, when)
    }

    /// Try to update the given repository data based on deltas.
    ///
    /// Returns an error in case this fails, e.g. because there not all applicable deltas
    /// available. Note that if this fails because one of the deltas can not be retrieved
    /// or applied for some some reason, then the repository data will still be modified.
    ///
    /// In short.. if this fails, fall back to a full re-sync based on the latest snapshot
    /// and discard the existing repository data.
    fn update_repository_data_from_deltas(
        mut notification: NotificationFile,
        etag: Option<String>,
        data: &mut RepositoryData,
        fetcher: &Fetcher,
        when: Time,
    ) -> Result<()> {
        // Check that the session matches our data. If not we should error out
        // so that a full re-sync is done.
        if notification.session_id() != data.session_id {
            return Err(anyhow!("session changed, cannot apply deltas"));
        }

        // Sort the deltas from low to high and check if the sequence
        // contains no gaps.
        if !notification.sort_and_verify_deltas(None) {
            return Err(anyhow!("there seem to be gaps in the deltas"));
        }

        // Ensure there ARE deltas
        let first_delta = notification
            .deltas()
            .first()
            .ok_or(anyhow!("notification file has no deltas"))?;

        // Ensure that we have all deltas needed for our
        // current data serial.
        if first_delta.serial() > data.serial + 1 {
            return Err(anyhow!(
                "no delta path from {} to {}",
                data.serial,
                notification.serial()
            ));
        }

        // Retrieve and apply deltas
        for delta_info in notification.deltas() {
            if delta_info.serial() != data.serial + 1 {
                // skip deltas that are already processed.
                continue;
            } else {
                let delta = Self::read_delta_file(fetcher, delta_info.uri(), delta_info.hash())?;
                for element in delta.into_elements() {
                    match element {
                        DeltaElement::Publish(publish) => {
                            let (uri, bytes) = publish.unpack();
                            data.objects.insert(uri.into(), bytes.into());
                        }
                        DeltaElement::Update(update) => {
                            let (uri, hash, bytes) = update.unpack();
                            let uri_string = UriString::from(&uri);
                            let existing = data
                                .objects
                                .get(&uri_string)
                                .ok_or(anyhow!(format!("no object to update at {uri}")))?;

                            if !hash.matches(existing.bytes().as_ref()) {
                                return Err(anyhow!(format!(
                                    "existing object at {uri} does not match update hash"
                                )));
                            }

                            data.objects.insert(uri_string, bytes.into());
                        }
                        DeltaElement::Withdraw(withdraw) => {
                            let (uri, hash) = withdraw.unpack();
                            let uri_string = UriString::from(&uri);

                            let existing = data
                                .objects
                                .get(&uri_string)
                                .ok_or(anyhow!(format!("no object to withdraw at {uri}")))?;

                            if !hash.matches(existing.bytes().as_ref()) {
                                return Err(anyhow!(format!(
                                    "existing object at {uri} does not match withdraw hash"
                                )));
                            }

                            data.objects.remove(&uri_string);
                        }
                    }
                }

                data.serial += 1;
            }
        }

        data.etag = etag;
        data.last_fetch = when;
        data.fetched = true;

        Ok(())
    }

    fn repository_data_from_snapshot(
        notification: NotificationFile,
        etag: Option<String>,
        fetcher: &Fetcher,
        when: Time,
    ) -> Result<RepositoryData> {
        let serial = notification.serial();
        let session_id = notification.session_id();

        let snapshot_uri_hash = notification.snapshot();
        let uri = snapshot_uri_hash.uri();
        let hash = snapshot_uri_hash.hash();
        trace!("Read and parse snapshot file for {uri}");
        let snapshot = Self::read_snapshot_file(fetcher, uri, hash)?;

        let elements = snapshot.into_elements();
        trace!("Processing {} objects", elements.len());

        let objects: HashMap<UriString, RepositoryObject> = elements
            .into_iter()
            .map(|e| {
                let (uri, bytes) = e.unpack();
                (uri.into(), RepositoryObject { bytes })
            })
            .collect();

        Ok(RepositoryData {
            etag,
            last_fetch: when,
            fetched: true,
            session_id,
            serial,
            objects,
        })
    }

    fn read_delta_file(fetcher: &Fetcher, uri: &uri::Https, hash: rrdp::Hash) -> Result<Delta> {
        let data = Self::read_bytes(fetcher, uri, hash)?;
        Delta::parse(data.as_ref()).with_context(|| format!("Cannot parse delta at uri: {uri}"))
    }

    fn read_snapshot_file(
        fetcher: &Fetcher,
        uri: &uri::Https,
        hash: rrdp::Hash,
    ) -> Result<Snapshot> {
        let data = Self::read_bytes(fetcher, uri, hash)?;
        Snapshot::parse(data.as_ref())
            .with_context(|| format!("Cannot parse snapshot at uri: {uri}"))
    }

    fn read_bytes(fetcher: &Fetcher, uri: &uri::Https, hash: rrdp::Hash) -> Result<Bytes> {
        let source = fetcher.resolve_source(uri)?;
        source.fetch(Some(hash), None, None)?.try_into_data()
    }

    fn get_fetcher(&self, notify_uri: &uri::Https) -> Arc<Fetcher> {
        self.fetchers.get(notify_uri).cloned().unwrap_or_else(|| {
            Arc::new(Fetcher::new(notify_uri.clone(), None, FetchMode::Insecure))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryData {
    // We use the etag to prevent re-fetching the complete
    // notify.xml if it has not changed.
    etag: Option<String>,

    // Track when we last fetched so that we can have a
    // cool-down before even attempting to check for an
    // updated notify.xml.
    last_fetch: Time,

    #[serde(skip_serializing, default)]
    fetched: bool,

    session_id: Uuid,
    serial: u64,
    objects: HashMap<UriString, RepositoryObject>,
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

impl From<Bytes> for RepositoryObject {
    fn from(bytes: Bytes) -> Self {
        RepositoryObject { bytes }
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

        let mut validator = Validator::new(vec![tal], vec![fetcher]);

        validator
            .validate_at(true, Time::utc(2023, 2, 13, 15, 58, 00))
            .unwrap();
    }
}
