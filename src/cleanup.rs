use crate::{config, util};
use crate::state::{PublicationTimestamps, RrdpSerialNumber, SecondsSinceEpoch};
use crate::rrdp::NotificationFile;

use anyhow::Result;
use walkdir::{DirEntry, WalkDir};

use std::path::{Path, PathBuf};

fn is_old_snapshot(serial: RrdpSerialNumber, last_serial: u64) -> bool {
    serial < last_serial
}

fn is_expired_serial(
    serial: RrdpSerialNumber,
    publication_timestamps: &PublicationTimestamps,
    expiration_time: SecondsSinceEpoch) -> bool
{
    // An RRDP serial is "expired" if the RRDP 8182 Notification File by the
    // same serial number, or a later Notification File, was published by us
    // more than expiration_time seconds ago.
    publication_timestamps.iter().any(|(pub_serial, pub_ts)| {
        *pub_serial >= serial && *pub_ts < expiration_time
    })
}

fn is_snapshot_file(entry: &DirEntry) -> Option<(PathBuf, RrdpSerialNumber)> {
    // <rrdp data dir>/<notification session id>/<rrdp serial number>/snapshot.xml
    // ^ depth 0       ^ depth 1                 ^ depth 2            ^ depth 3
    if entry.depth() == 3 && entry.file_type().is_file() && entry.file_name() == config::SNAPSHOT_FNAME {
        if let Some(parent) = entry.path().parent() {
            if parent.is_dir() {
                if let Some(parent_name) = parent.file_name() {
                    if let Ok(serial) = parent_name.to_string_lossy().parse::<RrdpSerialNumber>() {
                        return Some((entry.path().to_path_buf(), serial));
                    }
                }
            }
        }
    }
    None
}

fn is_delta_dir(entry: &DirEntry) -> Option<(PathBuf, RrdpSerialNumber)> {
    // <rrdp data dir>/<notification session id>/<rrdp serial number>
    // ^ depth 0       ^ depth 1                 ^ depth 2
    if entry.depth() == 2 && entry.file_type().is_dir() {
        if let Ok(serial) = entry.file_name().to_string_lossy().parse::<RrdpSerialNumber>() {
            return Some((entry.path().to_path_buf(), serial));
        }
    }
    None
}

fn is_rsync_backup_dir(entry: &DirEntry, rsync_data_parent_dir: &Path) -> Option<(PathBuf, RrdpSerialNumber)> {
    // ../<rsync data dir>.<rrdp serial number>
    // ^ depth 0  ^ depth 1
    if entry.depth() == 1 && entry.file_type().is_dir() {
        if Some(entry.file_name()) == rsync_data_parent_dir.file_name() {
            if let Some(ext) = entry.path().extension() {
                if let Ok(serial) = ext.to_string_lossy().parse::<RrdpSerialNumber>() {
                    return Some((entry.path().to_path_buf(), serial));
                }
            }
        }
    }
    None
}

pub fn cleanup_snapshots(
    path_to_cleanup: &Path,
    cleanup_after_ts: SecondsSinceEpoch,
    last_serial: RrdpSerialNumber,
    publication_timestamps: &PublicationTimestamps) -> Result<()>
{
    //      | client       | client    | server       | server    | server
    //      | retrieved    | retrieved | published    | published | deleted
    //      | notification | snapshot  | notification | snapshot  | snapshot
    // time | serial nr    | serial nr | serial nr    | serial nr | serial nr
    // -----+--------------+-----------+--------------+-----------+------------
    //  0   |              |           |              | 1         |           
    //  1   |              |           | 1            |           |           
    //  2   | 1            |           |              |           |            
    //  3   |              |           |              | 1,2       |           
    //  4   |              |           | 2            |           |           
    //  5   |              | 1         |              |           |            
    //  6   |              |           |              | 1,2,3     |                
    //  7   |              |           | 3            |           |           
    //  8   |              |           |              |           |           
    //  9   |              |           |              | 1,2,3,4   |                  
    // 10   |              |           | 4            |           |           
    // 11   |              |           |              |           |           
    // 12   |              |           |              |           |           
    // 13   |              |           |              |           |            
    // 14   |              |           |              |           | 1
    // 15   |              |           |              |           |            
    // 16   |              |           |              |           |            
    // 17   |              |           |              |           | 2
    // 18   |              |           |              |           |            
    // 19   |              |           |              |           |            
    // 20   |              |           |              |           | 3
    //
    // Where we will delete snapshot^N if:
    //   - N < latest published notification serial number
    //   - now <= publication_time(notification^(>N)) + cleanup_delay

    // Note: Is it certain that these files are called snapshot.xml? Isn't the
    // filename determined by the originally served RRDP 8182 Notification File
    // and can be anything? For Krill it is snapshot.xml, but perhaps not for a
    // different repository server.

    debug!("Remove dangling RRDP snapshots published after {}",
        util::human_readable_secs_since_epoch(cleanup_after_ts));

    if path_to_cleanup.is_dir() {
        let num_cleaned = WalkDir::new(&path_to_cleanup).into_iter()
            .filter_map(|e| is_snapshot_file(&e.unwrap()))
                .inspect(|(path, serial)| trace!("Found snapshot file for serial {}: {:?}", serial, path))
            .filter(|(_, serial)| is_old_snapshot(*serial, last_serial))
                .inspect(|(_, serial)| trace!("Snapshot {} is old", serial))
            .filter(|(_, serial)| is_expired_serial(*serial, publication_timestamps, cleanup_after_ts))
                .inspect(|(_, serial)| debug!("Snapshot {} is expired and will be deleted", serial))
            .fold(0, |acc, (path, serial)| {
                let acc = match std::fs::remove_file(&path) {
                    Ok(_)    => { trace!("File {:?} for serial {} has been deleted", path, serial); acc + 1 },
                    Err(err) => { error!("Failed to cleanup serial {} path {:?}: {}", serial, path, err); acc },
                };

                // also remove the notification.xml.<serial> if it exists
                let old_notification_xml_path = format!("{}.{}", &path_to_cleanup.join(config::NOTIFICATION_FNAME).display(), serial);
                match std::fs::remove_file(&old_notification_xml_path) {
                    Ok(_)    => trace!("File {:?} for serial {} has been deleted", old_notification_xml_path, serial),
                    Err(err) => error!("Failed to cleanup serial {} path {:?}: {}", serial, old_notification_xml_path, err),
                }

                acc
            });

        if num_cleaned > 0 {
            info!("Removed {} dangling expired RRDP snapshots", num_cleaned);
        }
    }

    Ok(())
}


pub fn cleanup_rsync_dirs(
    path_to_cleanup: &Path,
    cleanup_after_ts: SecondsSinceEpoch,
    last_serial: RrdpSerialNumber,
    publication_timestamps: &PublicationTimestamps) -> Result<()>
{
    debug!("Remove old rsync directory backups published after {}",
        util::human_readable_secs_since_epoch(cleanup_after_ts));

    if path_to_cleanup.is_dir() {
        if let Some(parent) = path_to_cleanup.parent() {
            let num_cleaned = WalkDir::new(&parent).into_iter()
                .filter_map(|e| is_rsync_backup_dir(&e.unwrap(), path_to_cleanup))
                    .inspect(|(path, serial)| trace!("Found rsync backup dir for serial {}: {:?}", serial, path))
                .filter(|(_, serial)| is_old_snapshot(*serial, last_serial))
                    .inspect(|(_, serial)| trace!("Serial {} is old", serial))
                .filter(|(_, serial)| is_expired_serial(*serial, publication_timestamps, cleanup_after_ts))
                    .inspect(|(_, serial)| debug!("Rsync backup for serial {} is expired and will be deleted", serial))
                .fold(0, |acc, (path, serial)| {
                    match std::fs::remove_dir_all(&path) {
                        Ok(_)    => { trace!("Rsync backup {:?} for serial {} has been deleted", path, serial); acc + 1 },
                        Err(err) => { error!("Failed to cleanup Rsync backup {:?} for serial {}: {}", path, serial, err); acc },
                    }
                });

            if num_cleaned > 0 {
                info!("Removed {} dangling expired Rsync backups", num_cleaned);
            }
        }
    }

    Ok(())
}

pub fn cleanup_deltas(
    path_to_cleanup: &Path,
    cleanup_after_ts: SecondsSinceEpoch,
    notify: &NotificationFile,
    publication_timestamps: &PublicationTimestamps) -> Result<()>
{
    fn is_orphaned_delta(serial: RrdpSerialNumber, notify: &NotificationFile) -> bool {
        // An RRDP delta is "orphaned" if it is not mentioned in the RRDP 8182
        // Notification File.
        notify.deltas.iter().find(|(delta_serial, _)| *delta_serial == serial).is_none()
    }

    debug!("Remove dangling RRDP deltas published after {}",
        util::human_readable_secs_since_epoch(cleanup_after_ts));

    if path_to_cleanup.is_dir() {
        let num_cleaned = WalkDir::new(&path_to_cleanup).into_iter()
        .filter_map(|e| is_delta_dir(&e.unwrap()))
            .inspect(|(path, serial)| trace!("Found delta dir for serial {}: {:?}", serial, path))
        .filter(|(_, serial)| is_orphaned_delta(*serial, notify))
            .inspect(|(_, serial)| trace!("Delta {} is orphaned", serial))
        .filter(|(_, serial)| is_expired_serial(*serial, &publication_timestamps, cleanup_after_ts))
            .inspect(|(_, serial)| debug!("Delta {} is expired and will be deleted", serial))
        .fold(0, |acc, (path, serial)| {
            let add = match std::fs::remove_dir_all(&path) {
                Ok(_)    => { trace!("Directory {:?} for delta {} has been deleted", &path, &serial); 1 },
                Err(err) => { error!("Failed to cleanup delta {} path {:?}: {}", &serial, &path, err); 0 },
            };
            acc + add
        });

        if num_cleaned > 0 {
            info!("Removed {} dangling expired RRDP deltas", num_cleaned);
        }
    }

    Ok(())
}