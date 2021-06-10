//! Responsible for the main krill-sync process

use anyhow::Result;

use crate::{config::Config, rrdp::RrdpState, rsync};

pub fn process(config: Config) -> Result<()> {
    info!("Checking: {}", config.notification_uri);

    // ===================================================================
    // Get the current RRDP state:
    //  - recover and update if prior state exists; or
    //  - create a new state based on config
    // ===================================================================
    let mut changed = true;
    let mut rrdp_state = if config.state_path().exists() {
        let mut recovered = RrdpState::recover(&config.state_path())?;
        changed = recovered.update(&config.fetcher())?;
        recovered
    } else {
        RrdpState::create(&config)?
    };

    // ===================================================================
    // If enabled, use the remote RRDP data to create a local copy of the
    // repository in the format needed to serve it as an Rsync repository.
    // ===================================================================

    // Note that we do NOT fetch from a remote Rsync repository using the Rsync
    // protocol. Rather we fetch from a remote RRDP repository and represent it
    // locally in a form suitable for serving via an Rsync server daemon. This
    // is both to ensure consistency (the RRDP notification XML is a safe
    // starting point for fetching everything it refers to) and to avoid having
    // to use an external rsync client.
    //
    // We update the local Rsync repository representation before updating the
    // RRDP notification file because the RRDP XML files contain "uri" attribute
    // values that refer to the locations within the Rsync repository.
    //
    // If there was an existing current rsync directory then it will be kept
    // around for existing client. On unix systems we will use a symlink to point
    // to the current directory so that new client will get the updated content.
    // On non-unix systems we will rename directories in quick succession.
    //
    // We will also clean out old rsync directories if they had been deprecated
    // for more than the 'cleanup_after' time.
    if changed && config.rsync_enabled() {
        rsync::update_from_rrdp_state(&rrdp_state, &config)?;
    }

    // ============================
    // Update the local RRDP files.
    // ============================

    // This will write the new snapshot and and any missing delta files to disk
    // first, and then updates the notification file after a configurable delay.
    if changed {
        rrdp_state.write_rrdp_files(config.rrdp_notify_delay)?;
    }

    // Clean up any RRDP files and empty parent directories if they had been
    // deprecated for more than the configured 'cleanup_after' time.
    rrdp_state.clean(&config)?;

    // ==============
    // Persist state.
    // ==============

    // This allows future runs to pick up deltas rather than snapshots, and
    // will allow use to know which files can be safely cleaned up.
    rrdp_state.persist(&config.state_path())?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;
    use std::time::Duration;

    use crate::config::create_test_config;
    use crate::util::{https, test_with_dir};

    use super::*;

    #[test]
    fn build_from_clean_state() {
        test_with_dir("process_build_from_clean_state", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let config = create_test_config(&dir, notification_uri, source_uri_base);

            process(config).unwrap();
        })
    }

    #[test]
    fn build_update_clean() {
        test_with_dir("process_build_update_clean", |dir| {

            // Build up state for the first time
            let config_2656 = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2656/"
            );
            process(config_2656).unwrap();
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/notification.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2653/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2652/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rsync/current");
            assert_file_dir_exists("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656");
            
            // Then update state immediately. We expect that this works AND that old
            // deprecated files and folders are kept.
            let config_2657 = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2657/"
            );
            process(config_2657).unwrap();
            
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/notification.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/snapshot.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2653/delta.xml");
            
            // even though the snapshot for 2656 and delta for 2652 are deprecated, they are still kept for the 'cleanup_after' period
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2652/delta.xml");
                        
            assert_file_dir_exists("./test/process_build_update_clean/rsync/current");
            assert_file_dir_exists("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656");
            assert_file_dir_exists("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2657");

            // Wait until after the test `cleanup_after` time of 2 seconds and update
            // to a further state. We expect that this works AND that old deprecated
            // files and folders are removed.
            std::thread::sleep(Duration::from_secs(3));

            let config_2658_no_delta = create_test_config(
                &dir,
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml"),
                "./test-resources/rrdp-rev2658-no-delta/"
            );
            process(config_2658_no_delta).unwrap();

            assert_file_dir_exists("./test/process_build_update_clean/rrdp/notification.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2658/snapshot.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2658/delta.xml");

            // The following are *just* now deprecated (no longer in the new notification.xml for 2658) but kept around
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/snapshot.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2657/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2655/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2654/delta.xml");
            assert_file_dir_exists("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2653/delta.xml");

            // The following were deprecated in 2657 and will now be removed. The empty dir for 2652 should be removed as well.
            assert_file_dir_removed("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml");
            assert_file_dir_removed("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2652/delta.xml");
            assert_file_dir_removed("./test/process_build_update_clean/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2652");

            // the rsync dir for 2656 should now be removed
            assert_file_dir_exists("./test/process_build_update_clean/rsync/current");
            assert_file_dir_exists("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2658");            
            assert_file_dir_exists("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2657");
            assert_file_dir_removed("./test/process_build_update_clean/rsync/session_e9be21e7-c537-4564-b742-64700978c6b4_serial_2656");
        })
    }

    fn assert_file_dir_exists(path: &str) {
        let path = PathBuf::from(path);
        if !path.exists() {
            panic!("Path {:?} does not exist!", path);
        }
    }

    fn assert_file_dir_removed(path: &str) {
        let path = PathBuf::from(path);
        if path.exists() {
            panic!("Path {:?} was not removed!", path);
        }
    }

    #[test]
    fn build_from_clean_state_with_moves() {
        test_with_dir("process_build_from_clean_state_with_moves", |dir| {
            let notification_uri =
                https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base = "./test-resources/rrdp-rev2656/";

            let mut config = create_test_config(&dir, notification_uri, source_uri_base);
            config.rsync_dir_force_moves = true;

            process(config).unwrap();
        })
    }
}
