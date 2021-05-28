//! Responsible for the main krill-sync process

use anyhow::{anyhow, Result};

use crate::{config::Config, fetch::Fetcher, rsync};

pub fn process(config: Config) -> Result<()> {
       
    let fetcher = Fetcher::new(config.notification_uri.clone(), config.fetch_map.clone());
    info!("Checking: {}", config.notification_uri);

    let rrdp_state = fetcher.rrdp_state()?;

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
    // Fetching a complete snapshot.xml can take a while for a large repository
    // Given that even when the snapshot changes that the majority of the
    // content is the same from one snapshot XML to the next, it's more
    // efficient to apply deltas to the last snapshot XML to create the new
    // snapshot XML than it is to download the entire snapshot XML. We want to
    // be able to update at worst once a minute. It might be much faster over an
    // internal connection but if it's fast enough over the public Internet it
    // will be fast enough for now and hopefully in the future too.
    //
    // If we don't have a prior snapshot XML or are missing a delta (it's been
    // too long since we last updated) we will not be able to apply delta
    // changes to it and thus are forced to download the entire snapshot XML.
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