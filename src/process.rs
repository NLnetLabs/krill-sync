//! Responsible for the main krill-sync process

use anyhow::{Context, Result};

use crate::{config::Config, fetch::Fetcher, file_ops, rrdp::RrdpState, rsync};

pub fn process(config: Config) -> Result<()> {
       
    let fetcher = Fetcher::new(config.notification_uri.clone(), config.fetch_map.clone());
    info!("Checking: {}", config.notification_uri);

    let state_path = config.state_dir.join("current.json");

    // TODO: recover rrdp_state from disk if it is present.
    //       if it is present but unusable... fall back to
    //       clean or exit? (allow config option for this?)
    let rrdp_state = RrdpState::create(&fetcher)?;

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
        rsync::build_repo_from_rrdp_snapshot(
            &rrdp_state,
            &config
        )?;

        // let seconds_since_epoch = Utc::now().timestamp();
        // new_state
        //     .rsync_publication_timestamps
        //     .insert(new_state.notify_serial, seconds_since_epoch);
    }

    // ===================================================
    // Update the local RRDP snapshot and delta XML files.
    // ===================================================
    
    // A normal Relying Party client would only need either the snapshot XML or
    // the delta XMLs, not both, but we need to be able to output copies of both
    // the snapshot and delta XMLs to be served to RP clients.
    //
    if config.rrdp_enabled() {
        rrdp_state.write_snapshot(&config.rrdp_dir)?;
        rrdp_state.write_missing_deltas(&config.rrdp_dir)?;
        
        if config.rrdp_notify_delay > 0 {
            info!("Waiting {} seconds before writing RRDP notification file", config.rrdp_notify_delay);
            std::thread::sleep(std::time::Duration::from_secs(config.rrdp_notify_delay));
        }
        
        rrdp_state.write_notification(&config.rrdp_dir, &config.notification_uri)?;
    }
    
    // ==============
    // Persist state.
    // ==============

    // This allows future runs to pick up deltas rather than snapshots, and
    // will allow use to know which files can be safely cleaned up.
    let json = serde_json::to_string_pretty(&rrdp_state)?;
    
    file_ops::write_buf(&state_path, json.as_bytes())
        .with_context(|| "Could not save state.")?;
    
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::util::{https, test_with_dir};
    use crate::config::create_test_config;

    use super::*;
    
    #[test]
    fn build_from_clean_state() {

        test_with_dir("process_build_from_clean_state", |dir| {
            let notification_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base ="./test-resources/rrdp/";
    
            let config = create_test_config(&dir, notification_uri, source_uri_base);

            process(config).unwrap();
        })
    }

    #[test]
    fn build_from_clean_state_with_moves() {

        test_with_dir("process_build_from_clean_state_with_moves", |dir| {
            let notification_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
            let source_uri_base ="./test-resources/rrdp/";
    
            let mut config = create_test_config(&dir, notification_uri, source_uri_base);
            config.rsync_dir_force_moves = true;

            process(config).unwrap();
        })
    }

}