use std::{
    fmt::{self, Debug},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::{
    blocking::Client,
    header::{ETAG, IF_NONE_MATCH, USER_AGENT},
    StatusCode,
};

use rpki::{
    rrdp::{Delta, DeltaInfo, Hash, NotificationFile, Snapshot, SnapshotInfo},
    uri,
};

use crate::{config, file_ops};

//------------ FetchResponse -------------------------------------------------
pub enum FetchResponse {
    Data { bytes: Bytes, etag: Option<String> },
    UnModified,
}

//------------ NotificationFileResponse --------------------------------------
pub enum NotificationFileResponse {
    Data {
        notification: NotificationFile,
        etag: Option<String>,
    },
    Unmodified,
}

impl NotificationFileResponse {
    pub fn content(self) -> Result<(NotificationFile, Option<String>)> {
        match self {
            NotificationFileResponse::Data { notification, etag } => Ok((notification, etag)),
            NotificationFileResponse::Unmodified => {
                Err(anyhow!("Cannot get content from unmodified response"))
            }
        }
    }
}

//------------ FetchSource ---------------------------------------------------
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchSource {
    File(PathBuf),
    Uri(uri::Https),
}

impl FetchSource {
    /// Gets the data from the fetch source, and verifies that it matches
    /// the hash - if it is provided.
    pub fn fetch(&self, hash: Option<Hash>, etag: Option<&String>) -> Result<FetchResponse> {
        let fetch_response = match self {
            FetchSource::Uri(uri) => {
                let mut request_builder = Client::builder().build()?.get(uri.as_str());
                request_builder = request_builder.header(USER_AGENT, config::USER_AGENT);

                if let Some(etag) = etag {
                    request_builder = request_builder.header(IF_NONE_MATCH, etag);
                }

                let response = request_builder
                    .send()
                    .with_context(|| format!("Could not GET: {}", uri))?;

                match response.status() {
                    StatusCode::OK => {
                        let etag = match response.headers().get(ETAG) {
                            None => None,
                            Some(header_value) => Some(
                                header_value
                                    .to_str()
                                    .with_context(|| "invalid ETag in response header")?
                                    .to_owned(),
                            ),
                        };

                        let bytes = response.bytes().with_context(|| {
                            format!(
                                "Got no response from '{}' even though the status was OK",
                                uri
                            )
                        })?;

                        Ok(FetchResponse::Data { bytes, etag })
                    }
                    StatusCode::NOT_MODIFIED => Ok(FetchResponse::UnModified),
                    _ => Err(anyhow!(
                        "Got unexpected HTTP response to GET for {}: {}",
                        uri,
                        response.status()
                    )),
                }
            }
            FetchSource::File(path) => {
                let bytes = file_ops::read_file(path).with_context(|| {
                    format!(
                        "Failed to read source from path: '{}'",
                        path.to_string_lossy()
                    )
                })?;
                Ok(FetchResponse::Data { bytes, etag: None })
            }
        }?;

        if let Some(hash) = hash {
            if let FetchResponse::Data { bytes, .. } = &fetch_response {
                if !hash.matches(bytes.as_ref()) {
                    return Err(anyhow!(
                        "Data at source: {} does not match hash '{}'",
                        self,
                        hash
                    ));
                }
            }
        }

        Ok(fetch_response)
    }

    fn fetch_no_etag(&self, hash: Option<Hash>) -> Result<Bytes> {
        match self.fetch(hash, None)? {
            FetchResponse::Data { bytes, .. } => Ok(bytes),
            FetchResponse::UnModified => {
                Err(anyhow!("Got unmodified response to fetch without ETag?!"))
            }
        }
    }

    fn join(&self, rel: &str) -> Result<FetchSource> {
        match self {
            FetchSource::File(base_path) => Ok(FetchSource::File(base_path.join(rel))),
            FetchSource::Uri(base_uri) => Ok(FetchSource::Uri(
                base_uri.join(rel.as_bytes()).with_context(|| {
                    format!("Cannot map rel path '{}' to uri: {}", rel, base_uri)
                })?,
            )),
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            FetchSource::File(path) => path.is_dir(),
            FetchSource::Uri(uri) => uri.to_string().ends_with('/'),
        }
    }
}

impl fmt::Display for FetchSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FetchSource::Uri(uri) => {
                write!(f, "{}", uri)
            }
            FetchSource::File(path) => {
                write!(f, "file: {}", path.to_string_lossy())
            }
        }
    }
}

impl FromStr for FetchSource {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(uri) = uri::Https::from_str(s) {
            Ok(FetchSource::Uri(uri))
        } else {
            Ok(FetchSource::File(PathBuf::from(s)))
        }
    }
}

//------------ FetchMap ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FetchMap {
    base_uri: uri::Https,
    base_fetch: FetchSource,
}

impl FetchMap {
    pub fn new(base_uri: uri::Https, base_fetch: FetchSource) -> Self {
        FetchMap {
            base_uri,
            base_fetch,
        }
    }

    fn source(&self, uri: &uri::Https) -> Result<FetchSource> {
        let uri = uri.as_str();
        let base_uri = self.base_uri.as_str();

        match uri.strip_prefix(base_uri) {
            None => Err(anyhow!(
                "Cannot map source uri: '{}' to base uri: '{}'",
                uri,
                base_uri
            )),
            Some(rel) => self.base_fetch.join(rel),
        }
    }
}

//------------ Fetcher -------------------------------------------------------

#[derive(Debug)]
pub struct Fetcher {
    notification_uri: uri::Https,
    fetch_map: Option<FetchMap>,
}

impl Fetcher {
    pub fn new(notification_uri: uri::Https, fetch_map: Option<FetchMap>) -> Self {
        Fetcher {
            notification_uri,
            fetch_map,
        }
    }

    pub fn notification_uri(&self) -> &uri::Https {
        &self.notification_uri
    }

    pub fn read_notification_file(
        &self,
        etag: Option<&String>,
    ) -> Result<NotificationFileResponse> {
        let snapshot_source = self.resolve_source(&self.notification_uri)?;
        let resp = match snapshot_source.fetch(None, etag)? {
            FetchResponse::Data { bytes, etag } => {
                let notification = NotificationFile::parse(bytes.as_ref())
                    .with_context(|| "Failed to parse notification file")?;
                NotificationFileResponse::Data { notification, etag }
            }
            FetchResponse::UnModified => NotificationFileResponse::Unmodified,
        };

        Ok(resp)
    }

    pub fn read_snapshot_file(&self, info: &SnapshotInfo) -> Result<Snapshot> {
        let snapshot_source = self.resolve_source(info.uri())?;
        let bytes = snapshot_source.fetch_no_etag(Some(info.hash()))?;

        Snapshot::parse(bytes.as_ref()).with_context(|| "Failed to parse snapshot file")
    }

    /// Retrieves a delta file, resolving the given URI against the local fetch map
    /// if applicable. Will insist that the Hash matches the content of the delta file
    /// and that the delta is applicable to the given version.
    pub fn read_delta_file(&self, delta_info: &DeltaInfo) -> Result<Delta> {
        let uri = delta_info.uri();
        let hash = delta_info.hash();
        let serial = delta_info.serial();

        let delta_source = self.resolve_source(uri)?;
        let delta_bytes = delta_source.fetch_no_etag(Some(hash))?;

        let delta = Delta::parse(delta_bytes.as_ref()).with_context(|| {
            format!(
                "Failed to parse delta file for uri: {}, from location: {}",
                uri, delta_source
            )
        })?;

        if delta.serial() != serial {
            Err(anyhow!(format!(
                "Delta file for uri: {} had serial {} instead of {}",
                uri,
                delta.serial(),
                serial
            )))
        } else {
            Ok(delta)
        }
    }

    pub fn resolve_source(&self, uri: &uri::Https) -> Result<FetchSource> {
        match &self.fetch_map {
            None => Ok(FetchSource::Uri(uri.clone())),
            Some(map) => map.source(uri),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::util::https;

    use super::*;

    #[test]
    fn resolve_fetch_to_disk() {
        let base_path = PathBuf::from("test-resources/rrdp/");

        let base_fetch = FetchSource::File(base_path.clone());

        let base_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/");
        let notification_uri = base_uri.join(b"notification.xml").unwrap();

        let fetch_map = Some(FetchMap {
            base_uri,
            base_fetch,
        });

        let fetcher = Fetcher {
            notification_uri,
            fetch_map,
        };

        let file_source = fetcher
            .resolve_source(&https(
                "https://krill-ui-dev.do.nlnetlabs.nl/rrdp/foo/bar/bla.xml",
            ))
            .unwrap();
        let expected_file_source = FetchSource::File(base_path.join("foo/bar/bla.xml"));
        assert_eq!(file_source, expected_file_source);

        assert!(fetcher
            .resolve_source(&https("https://other.host/rrdp/foo.txt"))
            .is_err());
    }

    #[test]
    fn resolve_fetch_to_uri() {
        let base_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/");
        let notification_uri = base_uri.join(b"notification.xml").unwrap();

        let base_fetch = FetchSource::Uri(https("https://other.host/rrdp/"));

        let fetch_map = Some(FetchMap {
            base_uri,
            base_fetch,
        });

        let fetcher = Fetcher {
            notification_uri,
            fetch_map,
        };

        let file_source = fetcher
            .resolve_source(&https(
                "https://krill-ui-dev.do.nlnetlabs.nl/rrdp/foo/bar/bla.xml",
            ))
            .unwrap();
        let expected_file_source =
            FetchSource::Uri(https("https://other.host/rrdp/foo/bar/bla.xml"));
        assert_eq!(file_source, expected_file_source);

        assert!(fetcher
            .resolve_source(&https("https://other.host/rrdp/foo.txt"))
            .is_err());
    }
}
