use crate::file_ops;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub type PublicationTimestamps = BTreeMap<RrdpSerialNumber, SecondsSinceEpoch>;
pub type RrdpSerialNumber = u64;
pub type SecondsSinceEpoch = u64;

// Store the last RRDP serial that we downloaded in a state file because (a) it's
// harder and indirect to read it from the last downloaded notification file
// and (b) on systems that only serve an Rsync repository there won't even be
// a notification file to read it from or any notion of RRDP serial number.
#[derive(Default, Serialize, Deserialize)]
pub struct State {
    pub notify_uri: Option<String>,
    pub notify_etag: Option<String>,
    pub notify_serial: u64,
    pub publication_timestamps: PublicationTimestamps,
}

fn get_last_pub_time(publication_timestamps: &PublicationTimestamps) -> Option<&SecondsSinceEpoch> {
    publication_timestamps.get(publication_timestamps.keys().max()?)
}

pub fn load_state(state_path: &Path) -> Result<Option<State>> {
    if state_path.is_file() {
        debug!("Reading saved state from {:?}", &state_path);
        let file = File::open(&state_path)?;
        let reader = BufReader::new(file);
        let state: State = serde_json::from_reader(reader)?;

        // get the timestamp of the highest serial number that we have a record
        // of "publishing"
        let last_pub_ts = get_last_pub_time(&state.publication_timestamps);
        debug!("State loaded: uri: {:?}, last serial: {}, last publication: {:?}",
            state.notify_uri, state.notify_serial, last_pub_ts);

        Ok(Some(state))
    } else {
        Ok(None)
    }
}

pub fn save_state(state_path: &Path, state: &State) -> Result<()> {
    file_ops::write_buf(&state_path, &serde_json::to_vec_pretty(&state)?)
}