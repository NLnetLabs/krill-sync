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
    let rrdp_state = if config.state_path().exists() {
        let mut recovered = RrdpState::recover(&config.state_path())?;
        recovered.update(&config.fetcher())?;
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
    if config.rsync_enabled() {
        rsync::build_repo_from_rrdp_snapshot(&rrdp_state, &config)?;

        // let seconds_since_epoch = Utc::now().timestamp();
        // new_state
        //     .rsync_publication_timestamps
        //     .insert(new_state.notify_serial, seconds_since_epoch);
    }

    // ===================================================
    // Update the local RRDP snapshot and delta XML files.
    // ===================================================
    rrdp_state.write_rrdp_files(config.rrdp_notify_delay)?;

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
