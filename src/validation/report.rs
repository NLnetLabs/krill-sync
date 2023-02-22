use std::{collections::HashMap, convert::TryFrom, fmt, str::FromStr};

use rpki::{
    repository::{
        aspa::AsProviderAttestation,
        resources::{AddressFamily, Prefix, ResourceSet},
        roa::RouteOriginAttestation,
        ResourceCert,
    },
    uri,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Report the outcome of a validation run.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ValidationReport {
    pub certs: Vec<ValidatedCaCertificate>,
    pub rrdp_repositories: HashMap<uri::Https, RepositoryReport>,
}

impl ValidationReport {
    pub fn add_cert(&mut self, cert: ValidatedCaCertificate) {
        if let Some(rrdp_uri) = cert.ca_cert_info.sia_rrdp.clone() {
            let repo_stats = self.rrdp_repositories.entry(rrdp_uri).or_default();
            repo_stats.process_cert(&cert);
        }
        self.certs.push(cert);
    }

    pub fn add_other(&mut self, mut other: Self) {
        self.certs.append(&mut other.certs);

        for (uri, stats) in other.rrdp_repositories {
            if let Some(existing) = self.rrdp_repositories.get_mut(&uri) {
                existing.add_other(stats);
            } else {
                self.rrdp_repositories.insert(uri, stats);
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RepositoryReport {
    pub nr_ca_certs: usize,
    pub nr_roas: usize,
    pub nr_vrps: usize,
    pub nr_aspas: usize,
    pub nr_router_certs: usize,
    pub issues: Vec<ValidationIssue>,
}

impl RepositoryReport {
    fn process_cert(&mut self, cert: &ValidatedCaCertificate) {
        self.nr_ca_certs += cert.children.len();
        self.nr_roas += cert.roas.len();

        // We do not filter out unique VRPs here, but just count the number.
        // If we really want unique VRPs then we should also check ROAs issued
        // under other CA certificates - theoretically at least - they could
        // contain duplicate VRPs if other CA certificates have (some of) the
        // same resources as this certificate.
        //
        // So.. in short.. just counting the number of VRPs is fine for
        // these stats.
        let nr_vrps = cert.roas.iter().flat_map(|roa| &roa.vrps).count();

        self.nr_vrps += nr_vrps;
        self.nr_aspas += cert.aspas.len();
        self.nr_router_certs += cert.router_certs.len();

        if !cert.issues.is_empty() {
            let mut cert = cert.clone();
            self.issues.append(&mut cert.issues);
        }
    }

    fn add_other(&mut self, mut other: Self) {
        self.nr_ca_certs += other.nr_ca_certs;
        self.nr_roas += other.nr_roas;
        self.nr_vrps += other.nr_vrps;
        self.nr_aspas += other.nr_aspas;
        self.nr_router_certs += other.nr_router_certs;
        self.issues.append(&mut other.issues);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatedCaCertificate {
    pub ca_cert_info: ValidatedCaCertInfo,
    pub children: Vec<ValidatedChild>,
    pub router_certs: Vec<ValidatedRouterCert>,
    pub roas: Vec<ValidatedRoa>,
    pub aspas: Vec<ValidatedAspa>,
    pub ignored: Vec<IgnoredObjectInfo>,
    pub issues: Vec<ValidationIssue>,
}

impl ValidatedCaCertificate {
    pub fn empty(ca_cert_info: ValidatedCaCertInfo) -> Self {
        ValidatedCaCertificate {
            ca_cert_info,
            children: vec![],
            router_certs: vec![],
            roas: vec![],
            aspas: vec![],
            ignored: vec![],
            issues: vec![],
        }
    }

    pub fn add_child(&mut self, child: ValidatedChild) {
        self.children.push(child);
    }

    pub fn add_router_cert(&mut self, router_cert: ValidatedRouterCert) {
        self.router_certs.push(router_cert);
    }

    pub fn add_roa(&mut self, roa: ValidatedRoa) {
        self.roas.push(roa);
    }

    pub fn add_aspa(&mut self, aspa: ValidatedAspa) {
        self.aspas.push(aspa);
    }

    pub fn add_ignored(&mut self, ignored: IgnoredObjectInfo) {
        self.ignored.push(ignored);
    }

    pub fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatedRoa {
    uri: uri::Rsync,
    vrps: Vec<RoaPayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatedChild {
    uri: uri::Rsync,
    cert_info: ValidatedCaCertInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatedRouterCert {
    uri: uri::Rsync,
    //todo: router key info
}

impl ValidatedRouterCert {
    pub fn new(uri: uri::Rsync) -> Self {
        ValidatedRouterCert { uri }
    }
}

impl ValidatedChild {
    pub fn new(uri: uri::Rsync, cert_info: ValidatedCaCertInfo) -> Self {
        ValidatedChild { uri, cert_info }
    }
}

impl ValidatedRoa {
    pub fn make(uri: uri::Rsync, roa: RouteOriginAttestation) -> Self {
        let asn = AsNumber(roa.as_id().into_u32());

        let mut vrps = vec![];

        for pfx in roa.v4_addrs().iter() {
            vrps.push(RoaPayload {
                asn,
                prefix: TypedPrefix::V4(Ipv4Prefix(pfx.prefix())),
                max_length: pfx.max_length(),
            });
        }

        for pfx in roa.v6_addrs().iter() {
            vrps.push(RoaPayload {
                asn,
                prefix: TypedPrefix::V6(Ipv6Prefix(pfx.prefix())),
                max_length: pfx.max_length(),
            });
        }

        ValidatedRoa { uri, vrps }
    }
}

/// TODO: Use ROA payload from core krill once krill-sync and
///       krill are merged. Or.. rather put all of that in
///       krill-commons or something if/when we split krill into
///       sub-projects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaPayload {
    asn: AsNumber,
    prefix: TypedPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_length: Option<u8>,
}

//------------ ValidatedAspa -----------------------------------------------

/// TODO: Use krill type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ValidatedAspa {
    uri: uri::Rsync,
    customer: AsNumber,
    providers: Vec<AspaProvider>,
}

impl ValidatedAspa {
    pub fn make(uri: uri::Rsync, aspa: AsProviderAttestation) -> Self {
        let customer = AsNumber(aspa.customer_as().into_u32());
        let providers = aspa
            .provider_as_set()
            .iter()
            .map(|p| {
                let afi_limit = match p.afi_limit() {
                    None => AspaLimit::None,
                    Some(limit) => match limit {
                        AddressFamily::Ipv4 => AspaLimit::IPv4,
                        AddressFamily::Ipv6 => AspaLimit::IPv6,
                    },
                };
                AspaProvider {
                    provider: AsNumber(p.provider().into_u32()),
                    afi_limit,
                }
            })
            .collect();

        ValidatedAspa {
            uri,
            customer,
            providers,
        }
    }
}

/// TODO: Use krill type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AspaProvider {
    provider: AsNumber,
    afi_limit: AspaLimit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AspaLimit {
    None,
    IPv4,
    IPv6,
}

//------------ AsNumber ----------------------------------------------------
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AsNumber(u32);

//------------ TypedPrefix -------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TypedPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl FromStr for TypedPrefix {
    type Err = AuthorizationFmtError;

    fn from_str(prefix: &str) -> Result<Self, Self::Err> {
        if prefix.contains('.') {
            Ok(TypedPrefix::V4(Ipv4Prefix(
                Prefix::from_v4_str(prefix.trim())
                    .map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        } else {
            Ok(TypedPrefix::V6(Ipv6Prefix(
                Prefix::from_v6_str(prefix.trim())
                    .map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        }
    }
}

impl fmt::Display for TypedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TypedPrefix::V4(pfx) => pfx.fmt(f),
            TypedPrefix::V6(pfx) => pfx.fmt(f),
        }
    }
}

impl Serialize for TypedPrefix {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for TypedPrefix {
    fn deserialize<D>(d: D) -> Result<TypedPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        TypedPrefix::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

//------------ AuthorizationFmtError -------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationFmtError {
    Pfx(String),
    Asn(String),
    Auth(String),
    Delta(String),
}

impl fmt::Display for AuthorizationFmtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthorizationFmtError::Pfx(s) => write!(f, "Invalid prefix string: {s}"),
            AuthorizationFmtError::Asn(s) => write!(f, "Invalid asn in string: {s}"),
            AuthorizationFmtError::Auth(s) => write!(f, "Invalid authorization string: {s}"),
            AuthorizationFmtError::Delta(s) => {
                write!(f, "Invalid authorization delta string: {s}")
            }
        }
    }
}

impl AuthorizationFmtError {
    fn pfx(s: &str) -> Self {
        AuthorizationFmtError::Pfx(s.to_string())
    }

    pub fn auth(s: &str) -> Self {
        AuthorizationFmtError::Auth(s.to_string())
    }

    pub fn delta(s: &str) -> Self {
        AuthorizationFmtError::Delta(s.to_string())
    }
}

//------------ Ipv4Prefix --------------------------------------------------
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Ipv4Prefix(Prefix);

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.0.to_v4(), self.0.addr_len())
    }
}

impl fmt::Debug for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

//------------ Ipv6Prefix --------------------------------------------------
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Ipv6Prefix(Prefix);

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.0.to_v6(), self.0.addr_len())
    }
}

impl fmt::Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IgnoredObjectInfo {
    uri: uri::Rsync,
    reason: String,
}

impl IgnoredObjectInfo {
    pub fn new(uri: uri::Rsync, reason: impl fmt::Display) -> Self {
        IgnoredObjectInfo {
            uri,
            reason: reason.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationIssue {
    pub uri: Option<uri::Rsync>,
    pub msg: String,
}

impl ValidationIssue {
    pub fn with_uri_and_msg(uri: uri::Rsync, msg: impl fmt::Display) -> Self {
        ValidationIssue {
            uri: Some(uri),
            msg: msg.to_string(),
        }
    }
}

///         - Validity Time
///         - Parent cert URI (option: TA has no parent)
///         - SIA
///             - MFT
///             - CA
///             - RRDP (Option)
///         - Resources (inherit resolved)
///              - IPv4
///              - IPv6
///              - ASN
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatedCaCertInfo {
    pub sia_mft: uri::Rsync,
    pub sia_ca: uri::Rsync,
    pub sia_rrdp: Option<uri::Https>,
    pub resources: ResourceSet,
}

impl TryFrom<&ResourceCert> for ValidatedCaCertInfo {
    type Error = &'static str;

    fn try_from(resource_cert: &ResourceCert) -> Result<Self, Self::Error> {
        let sia_rrdp = resource_cert.rpki_notify().cloned();
        let sia_ca = resource_cert
            .ca_repository()
            .cloned()
            .ok_or("Certificate has no SIA CA")?;
        let sia_mft = resource_cert
            .rpki_manifest()
            .cloned()
            .ok_or("Certificate has no SIA Manifest")?;

        let ipv4 = resource_cert.v4_resources().clone().into();
        let ipv6 = resource_cert.v6_resources().clone().into();
        let asns = resource_cert.as_resources().clone();
        let effective_resources = ResourceSet::new(asns, ipv4, ipv6);

        Ok(ValidatedCaCertInfo {
            sia_mft,
            sia_ca,
            sia_rrdp,
            resources: effective_resources,
        })
    }
}
