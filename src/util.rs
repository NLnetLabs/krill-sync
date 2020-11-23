use chrono::{Local, TimeZone};

pub fn human_readable_secs_since_epoch(secs_since_epoch: i64) -> String {
    Local.timestamp(secs_since_epoch, 0).to_rfc3339()
}