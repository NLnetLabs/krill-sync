use std::path::Path;
use anyhow::{Result, anyhow};

use krill_sync::config::{ configure, Config };
use krill_sync::file_ops::write_buf;
use krill_sync::process::process;

fn main() {
    if let Err(err) = configure_and_try_main() {
        eprintln!("{:?}", err);
        std::process::exit(1);
    }
}

fn configure_and_try_main() -> Result<()> {
    try_main(configure()?)
}

fn try_main(config: Config) -> Result<()> {
    let pid_file = config.pid_file.to_owned();
    if let Err(err) = lock(&pid_file) {
        return Err(anyhow!(
            "Failed to create lock file {:?}: {} (tip: use --pid-file to \
            change the location of the lock file) ",
            &pid_file,
            err
        ));
    }

    let process_res = process(config);
    if let Err(e) = unlock(&pid_file) {
        eprint!("Failed to remove pid file {:?}: {}", pid_file, e);
    }

    process_res
}


pub fn lock(pid_file: &Path) -> Result<()> {
    if pid_file.is_file() {
        return Err(anyhow!("Lock file {:?} exists, aborting", &pid_file));
    }
    write_buf(&pid_file, &format!("{}\n", std::process::id()).as_bytes().to_vec())?;

    // Ensure the lock file is removed even if we are killed by SIGINT or SIGTERM
    let unlock_pid_file = pid_file.to_owned();
    ctrlc::set_handler(move || {
        eprintln!("CTRL-C caught, aborting.");
        unlock(&unlock_pid_file).unwrap();
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler");

    Ok(())
}

pub fn unlock(pid_file: &Path) -> Result<()> {
    if pid_file.is_file() {
        std::fs::remove_file(pid_file)?;
    }

    Ok(())
}

// mod cleanup;
// mod config;
// mod file_ops;
// mod http;
// mod lock;
// mod rrdp;
// mod rsync;
// mod state;
// mod util;

// use crate::config::{Format, Opt};
// use crate::http::DownloadResult;
// use crate::rrdp::NotificationFile;
// use crate::state::SecondsSinceEpoch;
// use crate::state::State;
// use chrono::Utc;

// use anyhow::{anyhow, Result};
// use routinator::rpki::rrdp::UriAndHash;



// fn is_rsync_format_enabled(opt: &Opt) -> bool {
//     opt.format == Format::Both || opt.format == Format::Rsync
// }

// fn warn_about_unexpected_etag_values(prev_etag: &Option<String>, new_etag: &Option<String>) {
//     if let Some(new_etag) = new_etag {
//         if let Some(prev_etag) = prev_etag {
//             if prev_etag == new_etag {
//                 warn!(
//                     "RRDP notification file was re-served with an \
//                         unchanged ETag ({} == {}). This may indicate a \
//                         problem with the RRDP server. Processing anyway.",
//                     prev_etag, new_etag
//                 );
//             }
//         }
//     } else {
//         warn!(
//             "RRDP notification file was served without an ETag \
//                 header. Re-downloads can be avoided by adding an ETag \
//                 response header."
//         );
//     }
// }

// fn should_notification_file_be_processed(
//     notify: &NotificationFile,
//     opt: &Opt,
//     state: &State,
//     new_state: &State,
// ) -> Result<bool> {
//     match (
//         state.notify_serial,
//         notify.serial,
//         &state.notify_etag,
//         &new_state.notify_etag,
//     ) {
//         (prev_serial, new_serial, _, _) if prev_serial < new_serial => Ok(true),
//         (prev_serial, new_serial, Some(prev_etag), Some(new_etag)) if prev_etag != new_etag => {
//             warn!(
//                 "RRDP notification file is unchanged (by serial \
//                     check: {} == {}) but IS changed by ETag check: \
//                     {} != {}). Processing anyway",
//                 prev_serial, new_serial, prev_etag, new_etag
//             );
//             Ok(true)
//         }
//         (prev_serial, new_serial, _, _) if new_serial < prev_serial => Err(anyhow!(
//             "RDDP notification file serial is older than the last \
//                          seen serial: {} < {}, exiting.",
//             new_serial,
//             prev_serial
//         )),
//         _ if opt.force_update => Ok(true),
//         (prev_serial, new_serial, _, _) => {
//             info!(
//                 "RRDP notification file is unchanged (by serial check: \
//                 {} <= {}), exiting.",
//                 prev_serial, new_serial
//             );
//             Ok(false)
//         }
//     }
// }

// fn main() {
//     if let Err(err) = try_main() {
//         error!("{:?}", err);
//         std::process::exit(1);
//     }
// }

// fn try_main() -> Result<()> {

//     // Ensure the lock file is removed if we return from this function
//     let _ = scopeguard::guard(opt.pid_file.clone(), |lock_path| {
//         lock::unlock(&lock_path).unwrap();
//     });

//     let rrdp_http_client = http::create_client(opt.insecure);

//     // =========================================
//     // Load previously saved state, if available
//     // =========================================
//     let state_path = opt.state_dir.join("state");
//     let (state, state_loaded) = match state::load_state(&state_path)? {
//         Some(state) => (state, true),
//         None => (State::default(), false),
//     };
//     let mut new_state = state.clone();

//     let now: SecondsSinceEpoch = Utc::now().timestamp();
//     let cleanup_older_than_ts = now - opt.cleanup_after;

//     // ==========================
//     // Cleanup old snapshot files
//     // ==========================
//     cleanup::cleanup_snapshots(
//         &opt.rrdp_dir,
//         cleanup_older_than_ts,
//         state.notify_serial,
//         &new_state.rrdp_publication_timestamps,
//     )?;

//     // =============================
//     // Cleanup old rsync directories
//     // =============================
//     cleanup::cleanup_rsync_dirs(
//         &opt.rsync_dir,
//         cleanup_older_than_ts,
//         state.notify_serial,
//         &mut new_state.rsync_publication_timestamps,
//     )?;

//     // ============================================
//     // Download the RFC-8182 RRDP Notification File
//     // ============================================
//     let possible_raw_notification_file =
//         match rrdp::download_raw_rrdp_notification_file(&opt, &state, &rrdp_http_client)? {
//             None => {
//                 info!("RRDP notification file is unchanged (by ETag check)");
//                 None
//             }
//             Some(DownloadResult { body, etag }) => {
//                 new_state.notify_uri = Some(String::from(opt.notification_uri.as_str()));
//                 new_state.notify_etag = etag;
//                 Some(body)
//             }
//         };

//     let possible_update = match possible_raw_notification_file {
//         Some(raw_notification_file) => {
//             warn_about_unexpected_etag_values(&state.notify_etag, &new_state.notify_etag);

//             let notify = rrdp::parse_notification_file(&raw_notification_file)?;

//             if should_notification_file_be_processed(&notify, &opt, &state, &new_state)? {
//                 info!("Remote RRDP notification serial is {}", notify.serial);
//                 new_state.notify_serial = notify.serial;
//                 Some((raw_notification_file, notify))
//             } else {
//                 None
//             }
//         }
//         _ => None,
//     };

//     // ==============================
//     // Cleanup old notification files
//     // ==============================
//     cleanup::cleanup_notification_files(
//         &opt.rrdp_dir,
//         cleanup_older_than_ts,
//         state.notify_serial,
//         &state.rsync_publication_timestamps,
//     )?;

//     // =======================
//     // Cleanup old delta files
//     // =======================

//     if let Some((mut raw_notification_file, mut notify)) = possible_update {
//         // We can't do this until we have updated the RRDP 8182 Notification File,
//         // as deltas listed in the Notification File must not be deleted.
//         cleanup::cleanup_deltas(
//             &opt.rrdp_dir,
//             cleanup_older_than_ts,
//             &notify,
//             &mut new_state.rrdp_publication_timestamps,
//         )?;

//         // Prevent any possible fetches to the real target that would occur if the
//         // uri in the notify object is used as-is, instead modify it to point to the
//         // RRDP FQDN we were given on the command line.
//         notify.snapshot = UriAndHash::new(
//             rrdp::fix_uri(notify.snapshot.uri(), opt.notification_uri.authority())?,
//             notify.snapshot.hash().clone(),
//         );

//         // ======================================================
//         // Update previous or download new RFC-8182 Snapshot File
//         // ======================================================
//         let (raw_snapshot, generated) = rrdp::get_snapshot(
//             state_loaded,
//             &state,
//             &opt,
//             &mut notify,
//             &rrdp_http_client,
//             is_rrdp_format_enabled(&opt),
//         )?;
//         if generated {
//             // Calculate the hash of the new snapshot file and update the
//             // notification file to match. From RFC 8182:
//             //   "The hash attribute in snapshot and delta elements MUST be the
//             //    hexadecimal encoding of the SHA-256 [SHS] hash of the referenced
//             //    file.  The Relying Party MUST verify this hash when the file is
//             //    retrieved and reject the file if the hash does not match."
//             raw_notification_file = rrdp::update_notification_hash(
//                 raw_notification_file,
//                 &mut notify,
//                 rrdp::calc_hash(&raw_snapshot),
//             )?;
//         }


//         // ===================================================
//         // Update the local RRDP snapshot and delta XML files.
//         // ===================================================

//         // A normal Relying Party client would only need either the snapshot XML or
//         // the delta XMLs, not both, but we need to be able to output copies of both
//         // the snapshot and delta XMLs to be served to RP clients.
//         if is_rrdp_format_enabled(&opt) {
//             info!("Writing RRDP snapshot file");
//             let snapshot_dir_path = opt
//                 .rrdp_dir
//                 .join(rrdp::make_delta_dir_path(&notify, notify.serial)?);
//             let snapshot_file_path = snapshot_dir_path.join(config::SNAPSHOT_FNAME);
//             file_ops::write_buf(&snapshot_file_path, &raw_snapshot)?;

//             rrdp::download_deltas(&opt, &mut notify, &rrdp_http_client)?;
//         }

//         // ===============================
//         // Write out the notification file
//         // ===============================

//         // We write it at the end so that RRDP clients don't fetch it before the
//         // files it refers to are available.
//         if is_rrdp_format_enabled(&opt) {
//             if opt.rrdp_notify_delay > 0 {
//                 info!(
//                     "Waiting {} seconds before writing RRDP notification file",
//                     opt.rrdp_notify_delay
//                 );
//                 std::thread::sleep(std::time::Duration::from_secs(opt.rrdp_notify_delay))
//             }

//             info!("Performing atomic update of RRDP notification file");
//             let final_path = &opt.rrdp_dir.join(config::NOTIFICATION_FNAME);
//             let tmp_path = file_ops::set_path_ext(&final_path, config::TMP_FILE_EXT);
//             file_ops::write_buf(&tmp_path, &raw_notification_file)?;
//             file_ops::install_new_file(&final_path, state.notify_serial.to_string())?;

//             let seconds_since_epoch = Utc::now().timestamp();
//             new_state
//                 .rrdp_publication_timestamps
//                 .insert(new_state.notify_serial, seconds_since_epoch);
//         }
//     }

//     // Write out our state now that we have successfully finished
//     debug!("Writing state");
//     state::save_state(&state_path, &new_state)?;

//     Ok(())
// }
