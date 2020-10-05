use crate::config::{self, Opt};
use crate::file_ops;
use crate::http::HttpClient;
use crate::rrdp::NotificationFile;

use anyhow::{anyhow, Result};
use routinator::rpki::uri;

use std::path::PathBuf;
use std::str::FromStr;

fn make_rsync_repo_path(uri: &uri::Rsync) -> Result<PathBuf, std::convert::Infallible> {
    // Drop the module as the proper module name is determined by and part of
    // the rsyncd configuration and thus the user invoking krill-sync should
    // ensure that they direct krill-sync to write the rsync files out to the
    // directory that matches the location expected by rsyncd.
    PathBuf::from_str(uri.path())
}

pub fn build_repo_from_rrdp_snapshot(
    opt: &Opt,
    notify: &mut NotificationFile,
    client: &HttpClient,
    raw_snapshot: &[u8]) -> Result<()>
{
    info!("Updating Rsync repository");

    let tmp_out_path = file_ops::set_path_ext(&opt.rsync_dir, config::TMP_FILE_EXT);
    client.snapshot_from_buf(
        &notify,
        |uri| {
            let this_out_path = tmp_out_path.join(make_rsync_repo_path(&uri).unwrap());
            trace!("Writing Rsync file {:?}", &this_out_path);
            this_out_path
        },
        &raw_snapshot)
    .map_err(|err| anyhow!("Error updating Rsync repository: {:?}", &err))?;

    info!("Performing atomic update of the Rsync repository");
    file_ops::install_new_dir(&opt.rsync_dir)?;

    Ok(())
}