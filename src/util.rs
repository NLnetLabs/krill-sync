use std::fmt;

use bytes::Bytes;
use chrono::{Local, TimeZone};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

//----------------------------------------------------------------------------
//------------ Time Support --------------------------------------------------
//----------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialOrd, PartialEq, Serialize)]
pub struct Time(i64);

impl Time {
    pub fn now() -> Self {
        let now = Local::now();
        Time(now.timestamp())
    }

    pub fn seconds_ago(seconds: i64) -> Self {
        let mut now = Self::now();
        now.0 -= seconds;
        now
    }

    pub fn timestamp(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let time = Local.timestamp(self.0, 0);
        write!(f, "{}", time.to_rfc3339())
    }
}

//----------------------------------------------------------------------------
//------------ Serde Support -------------------------------------------------
//----------------------------------------------------------------------------

//------------ Bytes ---------------------------------------------------------

pub fn de_bytes<'de, D>(d: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let base64_str = String::deserialize(d)?;
    let bytes = base64::decode(&base64_str).map_err(serde::de::Error::custom)?;
    Ok(Bytes::from(bytes))
}

pub fn ser_bytes<S>(b: &Bytes, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64::encode(b).serialize(s)
}

//------------ Uuid ----------------------------------------------------------

pub fn de_uuid<'de, D>(d: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let uuid_str = String::deserialize(d)?;
    Uuid::parse_str(&uuid_str).map_err(serde::de::Error::custom)
}

pub fn ser_uuid<S>(uuid: &Uuid, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    uuid.to_string().serialize(s)
}

//----------------------------------------------------------------------------
//------------ Test Support --------------------------------------------------
//----------------------------------------------------------------------------
#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
const TEST_BASE_DIR: &str = "./test";

#[cfg(test)]
/// Create a test dir for a test so it can keep state there. If the dir is
/// present it will be delete first. Any failures will result in panics and
/// a failed test.
pub fn create_test_dir(test_name: &str) -> PathBuf {
    let path = PathBuf::from(format!("{}/{}", TEST_BASE_DIR, test_name));
    if path.exists() {
        std::fs::remove_dir_all(&path).unwrap();
    }
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[cfg(test)]
pub fn remove_test_dir(test_name: &str) {
    let path = PathBuf::from(format!("{}/{}", TEST_BASE_DIR, test_name));
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(test)]
pub fn test_with_dir<F>(test_name: &str, op: F)
where
    F: FnOnce(PathBuf),
{
    let path = create_test_dir(test_name);

    op(path);

    remove_test_dir(test_name);
}

#[cfg(test)]
pub fn https(s: &str) -> rpki::uri::Https {
    use std::str::FromStr;

    rpki::uri::Https::from_str(s).unwrap()
}
