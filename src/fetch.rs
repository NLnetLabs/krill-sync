use std::{
    fmt::{self, Debug},
    path::{Path, PathBuf},
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
    rrdp::{Hash, NotificationFile},
    uri::{self, Https},
};

use crate::{config, file_ops};

//------------ FetchResponse -------------------------------------------------
pub enum FetchResponse {
    Data { bytes: Bytes, etag: Option<String> },
    Saved,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchMode {
    Strict,
    Insecure, // accept self-signed or otherwise invalid HTTPs certificates.
}

impl FetchMode {
    fn accept_insecure(&self) -> bool {
        matches!(self, FetchMode::Insecure)
    }
}

//------------ FetchSource ---------------------------------------------------
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchSource {
    File(PathBuf),
    Uri(uri::Https, FetchMode),
}

impl FetchSource {
    #[cfg(test)]
    fn strict_uri(uri: uri::Https) -> Self {
        FetchSource::Uri(uri, FetchMode::Strict)
    }
}

impl FetchSource {
    /// Gets the data from the fetch source.
    /// - checks the hash if it is provided
    /// - uses the etag to avoid expensive http fetching if provided
    /// - if the target_file is provided then the data will be copied there
    ///   rather than be returned.
    pub fn fetch(
        &self,
        hash: Option<Hash>,
        etag: Option<&String>,
        target_file: Option<&Path>,
    ) -> Result<FetchResponse> {
        // Fetch the data into memory, even if we mean to write it to disk.
        // We could modify this to save straight to disk instead, but then
        // we would need to build up the hash as we are writing the file
        // for later checking, and then we should remove the file again if
        // the hash did not match.
        // Since the source files are trusted there should be no big deal
        // in keeping them temporarily in memory.
        let fetch_response = match self {
            FetchSource::Uri(uri, mode) => {
                let client = Client::builder()
                    .danger_accept_invalid_certs(mode.accept_insecure())
                    .danger_accept_invalid_hostnames(mode.accept_insecure())
                    .build()?;

                let mut request_builder = client.get(uri.as_str());
                request_builder = request_builder.header(USER_AGENT, config::USER_AGENT);

                if let Some(etag) = etag {
                    request_builder = request_builder.header(IF_NONE_MATCH, etag);
                }

                let response = request_builder
                    .send()
                    .with_context(|| format!("Could not GET: {uri}"))?;

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
                            format!("Got no response from '{uri}' even though the status was OK")
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

        // Verify the hash if provided
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

        if let Some(target_file) = target_file {
            if let FetchResponse::Data { bytes, .. } = &fetch_response {
                file_ops::write_buf(target_file, bytes)?;
                Ok(FetchResponse::Saved)
            } else {
                Ok(fetch_response)
            }
        } else {
            Ok(fetch_response)
        }
    }

    fn join(&self, rel: &str) -> Result<FetchSource> {
        match self {
            FetchSource::File(base_path) => Ok(FetchSource::File(base_path.join(rel))),
            FetchSource::Uri(base_uri, mode) => Ok(FetchSource::Uri(
                base_uri
                    .join(rel.as_bytes())
                    .with_context(|| format!("Cannot map rel path '{rel}' to uri: {base_uri}"))?,
                *mode,
            )),
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            FetchSource::File(path) => path.is_dir(),
            FetchSource::Uri(uri, _) => uri.to_string().ends_with('/'),
        }
    }
}

impl fmt::Display for FetchSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FetchSource::Uri(uri, mode) => match mode {
                FetchMode::Strict => write!(f, "{uri}"),
                FetchMode::Insecure => write!(f, "{uri} (accept insecure)"),
            },
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
            Ok(FetchSource::Uri(uri, FetchMode::Strict))
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
    mode: FetchMode,
}

impl Fetcher {
    pub fn new(notification_uri: uri::Https, fetch_map: Option<FetchMap>, mode: FetchMode) -> Self {
        Fetcher {
            notification_uri,
            fetch_map,
            mode,
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
        let resp = match snapshot_source.fetch(None, etag, None)? {
            FetchResponse::Data { bytes, etag } => {
                let notification = NotificationFile::parse(bytes.as_ref())
                    .with_context(|| "Failed to parse notification file")?;
                NotificationFileResponse::Data { notification, etag }
            }
            FetchResponse::UnModified => NotificationFileResponse::Unmodified,
            FetchResponse::Saved => {
                unreachable!("For the notification file we get data instead of saving")
            }
        };

        Ok(resp)
    }

    pub fn retrieve_file(&self, uri: &Https, hash: Hash, target: &Path) -> Result<()> {
        let source = self.resolve_source(uri)?;
        source
            .fetch(Some(hash), None, Some(target))
            .map_err(|e| anyhow!("Could not read snapshot: {}", e))?;

        Ok(())
    }

    pub fn resolve_source(&self, uri: &uri::Https) -> Result<FetchSource> {
        match &self.fetch_map {
            None => Ok(FetchSource::Uri(uri.clone(), self.mode)),
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
            mode: FetchMode::Strict,
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

        let base_fetch = FetchSource::strict_uri(https("https://other.host/rrdp/"));

        let fetch_map = Some(FetchMap {
            base_uri,
            base_fetch,
        });

        let fetcher = Fetcher {
            notification_uri,
            fetch_map,
            mode: FetchMode::Strict,
        };

        let file_source = fetcher
            .resolve_source(&https(
                "https://krill-ui-dev.do.nlnetlabs.nl/rrdp/foo/bar/bla.xml",
            ))
            .unwrap();
        let expected_file_source =
            FetchSource::strict_uri(https("https://other.host/rrdp/foo/bar/bla.xml"));
        assert_eq!(file_source, expected_file_source);

        assert!(fetcher
            .resolve_source(&https("https://other.host/rrdp/foo.txt"))
            .is_err());
    }
}
