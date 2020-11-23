use crate::{file_ops, util};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub type PublicationTimestamps = BTreeMap<RrdpSerialNumber, SecondsSinceEpoch>;
pub type RrdpSerialNumber = u64;
pub type SecondsSinceEpoch = i64; // same as Chrono::DateTime::timestamp()

// Store the last RRDP serial that we downloaded in a state file because (a) it's
// harder and indirect to read it from the last downloaded notification file
// and (b) on systems that only serve an Rsync repository there won't even be
// a notification file to read it from or any notion of RRDP serial number.
#[derive(Default, Serialize, Deserialize)]
pub struct State {
    pub notify_uri: Option<String>,
    pub notify_etag: Option<String>,
    pub notify_serial: u64,
    pub rrdp_publication_timestamps: PublicationTimestamps,
    pub rsync_publication_timestamps: PublicationTimestamps,
}

#[derive(Default, Serialize, Deserialize)]
pub struct BackwardCompatibleState {
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
        let state: State = match serde_json::from_reader(reader) {
            Ok(state) => Ok(state),
            Err(err) if err.is_data() => {
                let file = File::open(&state_path)?;
                let reader = BufReader::new(file);
                let old_format_state: BackwardCompatibleState = serde_json::from_reader(reader)?;
                info!("State file format is from a previous version and will be upgraded when saved");
                Ok(State {
                    notify_uri: old_format_state.notify_uri,
                    notify_etag: old_format_state.notify_etag,
                    notify_serial: old_format_state.notify_serial,
                    rrdp_publication_timestamps: old_format_state.publication_timestamps,
                    rsync_publication_timestamps: PublicationTimestamps::new(),
                })
            },
            Err(err) => Err(err)
        }?;

        // get the timestamp of the highest serial number that we have a record
        // of "publishing"
        let last_rrdp_pub_ts = get_last_pub_time(&state.rrdp_publication_timestamps).and_then(
            |&ts| Some(util::human_readable_secs_since_epoch(ts))
        );
        let last_rsync_pub_ts = get_last_pub_time(&state.rsync_publication_timestamps).and_then(
            |&ts| Some(util::human_readable_secs_since_epoch(ts))
        );
        debug!("State loaded: uri: {:?}, last serial: {}, last RRDP publication: {:?}, last Rsync publication: {:?}",
            state.notify_uri, state.notify_serial, last_rrdp_pub_ts, last_rsync_pub_ts);

        Ok(Some(state))
    } else {
        Ok(None)
    }
}

pub fn save_state(state_path: &Path, state: &State) -> Result<()> {
    file_ops::write_buf(&state_path, &serde_json::to_vec_pretty(&state)?)
}