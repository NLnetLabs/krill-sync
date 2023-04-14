use std::{process::Command, str::from_utf8};

use anyhow::{anyhow, Result};
use log::{debug, error, info};

use crate::{config::Config, rrdp::RrdpState, rsync};

/// Responsible for the main krill-sync process
pub fn process(config: &Config) -> Result<()> {
    info!("Checking: {}", config.notification_uri);

    // ===================================================================
    // Get the current RRDP state:
    //  - recover if prior state exists; or
    //  - create a new state based on config
    // ===================================================================
    let mut rrdp_state = if config.rrdp_state_path().exists() {
        RrdpState::recover(&config.rrdp_state_path())?
    } else {
        RrdpState::create(config)?
    };

    // ===================================================================
    // Update the RRDP state, if there are any changes in the source.
    // ===================================================================
    //
    // This will save new snapshot and delta files to the staging area
    // directory on disk and returns a list of these files.
    //
    // If there are no changes, i.e. the notification file is not changed,
    // then this list is empty and this is essentially a no-op.
    // ===================================================================
    let staged = match rrdp_state.update_staged(config)? {
        Some(staged) => staged,
        None => {
            debug!("No changes in RRDP content found");
            return Ok(());
        }
    };

    // ===================================================================
    // Pre-validate with internal validator.
    // ===================================================================
    //
    // Pre-validate the staged files. In case there are NO configured
    // TALs, then no actual validation is done, and any data from previous
    // validation runs will be removed from the RrdpState.
    //
    // If any validation issues are found, then dependent on configuration
    // we either just warn about this and continue (default), or exit with
    // an error.
    // ===================================================================
    rrdp_state.pre_validate(config)?;

    // ===================================================================
    // Pre-validate with configured scripts.
    // ===================================================================
    //
    // Call each configured script sequentially, and remember the exit
    // status for each script. We want to run each script even if there
    // is a failure, because it may be relevant to know if more than
    // one script fails.
    //
    // Log issues if found and then dependent on configuration either
    // continue, or exit.
    // ===================================================================
    {
        if !config.pre_validation_scripts.is_empty() {
            let mut issues = false;

            for script in &config.pre_validation_scripts {
                let output = Command::new(script).output()?;
                if output.status.success() {
                    info!(
                        "Validate staged repository files using {} ---> OK",
                        script.to_string_lossy()
                    );
                } else {
                    issues = true;

                    error!(
                        "Validate staged repository files using {} ---> FAILED",
                        script.to_string_lossy()
                    );
                    let std_output =
                        from_utf8(&output.stdout).unwrap_or("could not parse stdout output");

                    let error_output =
                        from_utf8(&output.stderr).unwrap_or("could not parse stderr output");

                    info!("{}", std_output);
                    error!("{}", error_output);
                }
            }
            if issues && config.tal_reject_invalid {
                return Err(anyhow!("Validation of staged repository files failed."));
            }
        }
    }

    // ===================================================================
    // Apply staged changes.
    // ===================================================================
    //
    // - updates the RrdpState with new content,
    // - deprecate old files
    // - move new snapshot and deltas to the target RRDP dir
    // - clean up old files, deprecated for the configured time
    // - move new notification file to the target RRDP dir
    rrdp_state.apply_staged_changed(staged, config)?;

    // ===================================================================
    // Update rsync state, if rsync support is enabled
    // ===================================================================
    //
    // Uses the latest local RRDP snapshot to create  a local copy of the
    // repository in the format needed to serve it as an Rsync repository.
    //
    // Note that we do NOT fetch from a remote Rsync repository using the
    // Rsync protocol. Rather we fetch from a remote RRDP repository and
    // represent it locally in a form suitable for serving via an Rsync
    // server daemon. This is both to ensure consistency (the RRDP
    // notification XML is a safe starting point for fetching everything
    // it refers to) and to avoid having to use an external rsync client.
    //
    // If there was an existing current rsync directory then it will be
    // kept around for existing clients. On unix systems we will use a
    // symlink to point to the current directory so that new client will
    // get the updated content.  On non-unix systems we will rename
    // directories in quick succession.
    //
    // We will also clean out old rsync directories if they had been
    // deprecated for more than the 'cleanup_after' time,.
    // ===================================================================
    if config.rsync_enabled() {
        rsync::update_from_rrdp_state(&rrdp_state, config)?;
    }

    // ===================================================================
    // Update the notification file if there was any change.
    // ===================================================================
    rrdp_state.write_notification(config.rrdp_notify_delay)?;

    // ===================================================================
    // Persist state
    // ===================================================================
    rrdp_state.persist(&config.rrdp_state_path())?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use std::path::Path;
    use std::time::Duration;

    use crate::config::create_test_config;
    use crate::util::{https, test_with_dir};

    use super::*;

    #[test]
    fn process_multiple_updates() {
        let rsync_dir_force_moves = false;
        let test_name = "process_multiple_updates";
        test_process(test_name, rsync_dir_force_moves)
    }

    #[test]
    fn process_multiple_updates_rsync_moves() {
        let rsync_dir_force_moves = true;
        let test_name = "process_multiple_updates_moves";
        test_process(test_name, rsync_dir_force_moves)
    }

    fn test_process(test_name: &str, rsync_dir_force_moves: bool) {
        test_with_dir(test_name, |dir| {
            // Build up state for the first time
            let config_2656 = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2656/",
                rsync_dir_force_moves,
            );
            process(&config_2656).unwrap();
            assert_file_dir_exists(&dir, "rrdp/notification.xml");
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml",
            );

            // note that the test config limits the number of deltas to 3
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml",
            );
            assert_file_dir_exists(&dir, "rsync/current");
            if !rsync_dir_force_moves {
                // when using moves, this dirname will only be created *after* it is
                // no longer current. Without moves we will find it immediately
                // and 'current' will be a symlink to it.
                assert_file_dir_exists(
                    &dir,
                    "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656",
                );
            }

            // Then update state immediately. We expect that this works AND that old
            // deprecated files and folders are kept.
            let config_2657 = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2657/",
                rsync_dir_force_moves,
            );
            process(&config_2657).unwrap();

            assert_file_dir_exists(&dir, "rrdp/notification.xml");
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/rnd-sn/snapshot.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/rnd-d/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml",
            );

            // even though the snapshot for 2656 and delta for 2654 are deprecated, they are still kept for the 'cleanup_after' period
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml",
            );

            assert_file_dir_exists(&dir, "rsync/current");
            assert_file_dir_exists(
                &dir,
                "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656",
            );
            if !rsync_dir_force_moves {
                assert_file_dir_exists(
                    &dir,
                    "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2657",
                );
            }

            // Wait until after the test `cleanup_after` time of 2 seconds and update
            // to a further state. We expect that this works AND that old deprecated
            // files and folders are removed.
            std::thread::sleep(Duration::from_secs(3));

            let config_2658_no_delta = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2658-no-delta/",
                rsync_dir_force_moves,
            );
            process(&config_2658_no_delta).unwrap();

            assert_file_dir_exists(&dir, "rrdp/notification.xml");
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2658/rnd-sn/snapshot.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2658/rnd-d/delta.xml",
            );

            // The following are *just* now deprecated (no longer in the new notification.xml for 2658) but kept around
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/rnd-sn/snapshot.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/rnd-d/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml",
            );
            assert_file_dir_exists(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml",
            );

            // The following were deprecated in 2657 and will now be removed. The empty dir for 2654 should be removed as well.
            assert_file_dir_removed(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/random-2656-sn/snapshot.xml",
            );
            assert_file_dir_removed(
                &dir,
                "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml",
            );
            assert_file_dir_removed(&dir, "rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654");

            // the rsync dir for 2656 should now be removed
            assert_file_dir_exists(&dir, "rsync/current");
            if !rsync_dir_force_moves {
                assert_file_dir_exists(
                    &dir,
                    "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2658",
                );
            }
            assert_file_dir_exists(
                &dir,
                "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2657",
            );
            assert_file_dir_removed(
                &dir,
                "rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656",
            );

            // Try a session reset
            let config_session_reset = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notifyerthingy.xml"),
                "./test-resources/rrdp-rev2-session-reset/",
                rsync_dir_force_moves,
            );
            process(&config_session_reset).unwrap();
            if !rsync_dir_force_moves {
                assert_file_dir_exists(
                    &dir,
                    "rsync/session_bf64ea72-ebb8-462f-99fb-8cd06f418565_serial_2",
                );
            }
        })
    }

    fn assert_file_dir_exists(dir: &Path, path: &str) {
        let path = dir.join(path);
        if !path.exists() {
            panic!("Path {} does not exist!", path.display());
        }
    }

    fn assert_file_dir_removed(dir: &Path, path: &str) {
        let path = dir.join(path);
        if path.exists() {
            panic!("Path {} was not removed!", path.display());
        }
    }

    #[test]
    fn rsync_include_host_name() {
        test_with_dir("rsync_include_host_name", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";
            let rsync_dir_force_moves = true;

            let mut config = create_test_config(
                &dir,
                notification_uri,
                source_uri_base,
                rsync_dir_force_moves,
            );
            config.rsync_include_host = true;

            process(&config).unwrap();

            assert_file_dir_exists(&dir, "rsync/current/krill-ui-dev.do.nlnetlabs.nl/repo");
        })
    }

    #[test]
    fn preserve_notification_file_name() {
        test_with_dir("preserve_notification_file_name", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notifyerthingy.xml");
            let source_uri_base = "./test-resources/rrdp-rev2-session-reset/";

            let rsync_dir_force_moves = true;

            let mut config = create_test_config(
                &dir,
                notification_uri,
                source_uri_base,
                rsync_dir_force_moves,
            );
            config.rsync_include_host = true;

            process(&config).unwrap();

            assert_file_dir_exists(&dir, "rsync/current");
            assert_file_dir_exists(&dir, "rrdp/notifyerthingy.xml");
        })
    }

    #[test]
    fn handle_empty_snapshot() {
        test_with_dir("handle_empty_snapshot", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-empty-snapshot/";

            let rsync_dir_force_moves = true;

            let mut config = create_test_config(
                &dir,
                notification_uri,
                source_uri_base,
                rsync_dir_force_moves,
            );
            config.rsync_include_host = true;

            process(&config).unwrap();

            assert_file_dir_exists(&dir, "rsync/current");
            assert_file_dir_exists(&dir, "rrdp/notification.xml");
        })
    }
}
