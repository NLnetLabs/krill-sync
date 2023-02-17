use std::{collections::HashMap, convert::TryFrom};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rpki::{
    repository::{
        aspa::Aspa, error::VerificationError, x509::Time, Cert, Crl, Manifest, ResourceCert, Roa,
    },
    rrdp::Snapshot,
    uri,
};

use crate::fetch::{FetchMode, Fetcher};

use super::{
    IgnoredObjectInfo, Tal, ValidatedAspa, ValidatedCaCertInfo, ValidatedCaCertificate,
    ValidatedChild, ValidatedRoa, ValidatedRouterCert, ValidationIssue, ValidationReport,
};

#[derive(Clone, Debug)]
pub struct Validator {
    tal: Tal,
    repositories: VisitedRepositories,
}

impl Validator {
    pub fn new(tal: Tal, fetchers: Vec<Fetcher>) -> Self {
        Validator {
            tal,
            repositories: VisitedRepositories {
                fetchers: fetchers
                    .into_iter()
                    .map(|f| (f.notification_uri().clone(), f))
                    .collect(),
                data: HashMap::new(),
            },
        }
    }

    pub fn validate(&mut self) -> Result<ValidationReport> {
        self.validate_at(Time::now())
    }

    pub fn validate_at(&mut self, when: Time) -> Result<ValidationReport> {
        let ta_cert = self.tal.validate_at(when)?;

        let info = ValidatedCaCertInfo::try_from(&ta_cert)
            .map_err(|e| anyhow!(format!("Invalid TA certificate: {e}")))?;

        Ok(self.validate_tree_at(&ta_cert, &info, when))
    }

    fn validate_tree_at(
        &mut self,
        resource_cert: &ResourceCert,
        ca_cert_info: &ValidatedCaCertInfo,
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
                    report.add(ca_cert);
                    return report;
                }
            };

            let data = match self.repositories.update(sia_rrdp) {
                Ok(data) => data,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        sia_ca.clone(),
                        format!("Could not get repo data from {sia_rrdp}: {e}"),
                    ));
                    report.add(ca_cert);
                    return report;
                }
            };

            let mft_bytes = match data.objects.get(mft_uri) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        "No manifest found",
                    ));
                    report.add(ca_cert);
                    return report;
                }
            };

            let mft = match Manifest::decode(mft_bytes.clone(), true) {
                Ok(mft) => mft,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        mft_uri.clone(),
                        format!("Cannot parse manifest: {e}"),
                    ));
                    report.add(ca_cert);
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
                    report.add(ca_cert);
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
                    report.add(ca_cert);
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
                    report.add(ca_cert);
                    return report;
                }
            };

            let crl_bytes = match data.objects.get(crl_uri) {
                Some(bytes) => bytes,
                None => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        crl_uri.clone(),
                        format!("CRL at {crl_uri} not found"),
                    ));
                    report.add(ca_cert);
                    return report;
                }
            };

            if crl_hash.verify(crl_bytes).is_err() {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri.clone(),
                    "CRL does not match hash on manifest",
                ));
                report.add(ca_cert);
                return report;
            };

            let crl = match Crl::decode(crl_bytes.clone()) {
                Ok(crl) => crl,
                Err(e) => {
                    ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                        crl_uri.clone(),
                        format!("Could not parse CRL: {e}"),
                    ));
                    report.add(ca_cert);
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
                report.add(ca_cert);
                return report;
            };

            if crl.next_update() < when {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    crl_uri.clone(),
                    "CRL is stale",
                ));
                report.add(ca_cert);
                return report;
            }

            if crl.contains(mft_cert.serial_number()) {
                ca_cert.add_issue(ValidationIssue::with_uri_and_msg(
                    mft_uri.clone(),
                    "Manifest was revoked",
                ));
                report.add(ca_cert);
                return report;
            }

            // Ok.. the CRL and Manifest are okay..
            //
            // We need at least a valid Manifest and CRL to validate
            // objects on the manifest. But we can now validate each
            // of those objects individually and just report issues
            // if applicable, but continue with the next object.
            for (uri, hash) in mft_entries.into_iter() {
                let bytes = match data.objects.get(&uri) {
                    Some(bytes) => bytes,
                    None => {
                        ca_cert
                            .add_issue(ValidationIssue::with_uri_and_msg(uri, "Object not found"));
                        continue;
                    }
                };

                if hash.verify(bytes).is_err() {
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
                    "roa" => match Roa::decode(bytes.clone(), true) {
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
                        match Cert::decode(bytes.clone()) {
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
                                    todo!("validate router cert ")
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
                    "asa" => match Aspa::decode(bytes.clone(), true) {
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
        report.add(ca_cert);

        // recurse child certificates
        for (cert, info) in child_certificates {
            report.add_all(self.validate_tree_at(&cert, &info, when));
        }

        report
    }
}

#[derive(Clone, Debug, Default)]
pub struct VisitedRepositories {
    fetchers: HashMap<uri::Https, Fetcher>,
    data: HashMap<uri::Https, RepositoryData>,
}

impl VisitedRepositories {
    fn update(&mut self, notify_uri: &uri::Https) -> Result<&RepositoryData> {
        if !self.data.contains_key(notify_uri) {
            let fetcher = self.get_fetcher(notify_uri)?;
            let (notification, _) = fetcher.read_notification_file(None)?.content()?;

            let snapshot_uri_hash = notification.snapshot();
            let snapshot_source = fetcher.resolve_source(snapshot_uri_hash.uri())?;
            let snapshot_data = snapshot_source
                .fetch(Some(snapshot_uri_hash.hash()), None, None)?
                .try_into_data()?;

            let snapshot = Snapshot::parse(snapshot_data.as_ref()).with_context(|| {
                format!("Cannot parse snapshot at uri: {}", snapshot_uri_hash.uri())
            })?;

            // let elements = snapshot.into_elements();
            // for e in elements {
            //     let (uri, bytes) = e.unpack();
            // }

            #[allow(clippy::mutable_key_type)]
            let objects: HashMap<uri::Rsync, Bytes> = snapshot
                .into_elements()
                .into_iter()
                .map(|e| e.unpack())
                .collect();

            self.data
                .insert(notify_uri.clone(), RepositoryData { objects });
        }

        self.data
            .get(notify_uri)
            .ok_or(anyhow!("No data for repository at: {}", notify_uri))
    }

    fn get_fetcher(&mut self, notify_uri: &uri::Https) -> Result<&Fetcher> {
        if !self.fetchers.contains_key(notify_uri) {
            let fetcher = Fetcher::new(notify_uri.clone(), None, FetchMode::Insecure);
            self.fetchers.insert(notify_uri.clone(), fetcher);
        }

        self.fetchers
            .get(notify_uri)
            .ok_or(anyhow!("No fetcher for repository at: {}", notify_uri))
    }
}

#[derive(Clone, Debug)]
pub struct RepositoryData {
    // todo: Track session and serial so we can apply deltas
    //       rather than getting the full snapshot.
    //       This only becomes relevant when we start using this from
    //       a daemon and/or persist this data between sync sessions.
    objects: HashMap<uri::Rsync, Bytes>,
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

        let mut validator = Validator::new(tal, vec![fetcher]);

        validator
            .validate_at(Time::utc(2023, 2, 13, 15, 58, 00))
            .unwrap();
    }
}
