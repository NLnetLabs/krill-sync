use std::sync::Arc;

use anyhow::{anyhow, Result};

use bytes::Bytes;
use rpki::{
    crypto::PublicKey,
    repository::{
        tal::{TalInfo, TalUri},
        x509::Time,
        Cert, ResourceCert,
    },
};
use serde::{Deserialize, Serialize};

use crate::fetch::{FetchMode, FetchSource};

/// A minimalistic Trust Anchor Locator
///
/// Contrary to real TALs this type only supports
/// one source for the TA certificate, which in this
/// case is a [`FetchSource`] so that it can be mapped
/// to disk (or later perhaps even memory) for testing
/// and/or efficiency.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tal {
    name: String,
    source: FetchSource,
    public_key: PublicKey,
}

impl Tal {
    /// Parses the given TAL. For our purpose we will use the first https
    /// uri only. If a source option is given, then the URI in the TAL file
    /// will be ignored and this source will be used instead.
    pub fn parse(name: String, tal_bytes: Bytes, source_opt: Option<FetchSource>) -> Result<Self> {
        let real_tal = rpki::repository::Tal::read_named(name.clone(), &mut tal_bytes.as_ref())
            .map_err(|e| anyhow!("Could not parse TAL: {}", e))?;

        let mut uri = None;
        for tal_uri in real_tal.uris() {
            if uri.is_none() {
                if let TalUri::Https(https_uri) = tal_uri {
                    uri = Some(https_uri.clone());
                }
            }
        }

        let uri = uri.ok_or_else(|| anyhow!("TAL does not contain valid https uri"))?;
        let source = source_opt.unwrap_or_else(|| FetchSource::Uri(uri, FetchMode::Insecure));

        let public_key = real_tal.key_info().clone();

        Ok(Tal {
            name,
            public_key,
            source,
        })
    }

    pub fn validate(&self) -> Result<ResourceCert> {
        self.validate_at(Time::now())
    }

    pub fn validate_at(&self, when: Time) -> Result<ResourceCert> {
        let fetched = self.source.fetch(None, None, None)?;
        let bytes = fetched.try_into_data()?;

        let cert =
            Cert::decode(bytes).map_err(|e| anyhow!("Cannot decode TA certificate: {}", e))?;

        let tal = Arc::new(TalInfo::from_name(self.name.clone()));

        let cert = cert
            .validate_ta_at(tal, true, when)
            .map_err(|e| anyhow!("Invalid TA certificate: {}", e))?;

        if cert.subject_public_key_info() != &self.public_key {
            Err(anyhow!("TA certificate public key does not match TAL"))
        } else {
            Ok(cert)
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn validate() {
        let tal_bytes = include_bytes!("../../test-resources/validation/good/ta.tal");
        let tal_bytes = Bytes::from_static(tal_bytes);
        let source = FetchSource::File(PathBuf::from("test-resources/validation/good/ta.cer"));

        let tal = Tal::parse("tal".to_string(), tal_bytes, Some(source)).unwrap();
        tal.validate_at(Time::utc(2023, 2, 13, 15, 58, 00)).unwrap();
    }
}
