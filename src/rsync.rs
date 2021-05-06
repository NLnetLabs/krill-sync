use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use chrono::Utc;
use routinator::rpki::uri;

use crate::config::{self, Opt};
use crate::file_ops;
use crate::http::HttpClient;
use crate::rrdp::NotificationFile;
use crate::state::RrdpSerialNumber;

fn authority_module_rsync_repo_path(uri: &uri::Rsync) -> Result<PathBuf, std::convert::Infallible> {
    // Include the module and authority in the rsync path.
    // rsyncd should be set up to use the proper rsync path, e.g.
    // [repository]
    // path = /data/rsync/rpki.example.org/repository
    // read only = true
    // list = true
    let authority = PathBuf::from_str(uri.module().authority());
    let module = PathBuf::from_str(uri.module().module());
    let path = PathBuf::from_str(uri.path());

    // TODO: validate that the following checks for path injection done:
    // authority/module starts with authority/
    // authority/module/path starts with authority/module/

    Ok(authority?.join(module?).join(path?))
}

fn path_only_rsync_repo_path(uri: &uri::Rsync) -> Result<PathBuf, std::convert::Infallible> {
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
    raw_snapshot: &[u8],
    last_serial: RrdpSerialNumber,
) -> Result<()> {
    info!("Updating Rsync repository");

    let out_path = if cfg!(unix) {
        let extension = format!("{}_{}", last_serial, Utc::now().timestamp());
        file_ops::set_path_ext(&opt.rsync_dir, &extension)
    } else {
        file_ops::set_path_ext(&opt.rsync_dir, config::TMP_FILE_EXT)
    };

    info!(
        "Writing Rsync repository to: {}",
        out_path.to_string_lossy()
    );
    write_rsync_content(&opt, &out_path, notify, client, raw_snapshot)?;

    if cfg!(unix) {
        info!(
            "Using symlink to link rsync module dir to the new content in {}",
            out_path.to_string_lossy()
        );
        // create a new symlink then rename it
        let tmp_name = file_ops::set_path_ext(&opt.rsync_dir, config::TMP_FILE_EXT);
        std::os::unix::fs::symlink(&out_path, &tmp_name)?;
        std::fs::rename(&tmp_name, &opt.rsync_dir)?;
    } else {
        info!("Renaming rsync folders for close to atomic update of the rsync module dir");
        file_ops::install_new_dir(&opt.rsync_dir, last_serial.to_string())?;
    }

    Ok(())
}

fn write_rsync_content(
    opt: &Opt,
    out_path: &Path,
    notify: &mut NotificationFile,
    client: &HttpClient,
    raw_snapshot: &[u8],
) -> Result<()> {
    let path_fn = if opt.full_rsync_path { authority_module_rsync_repo_path } else { path_only_rsync_repo_path };

    client
        .snapshot_from_buf(
            &notify,
            |uri| {
                let this_out_path = out_path.join(path_fn(&uri).unwrap());
                trace!("Writing Rsync file {:?}", &this_out_path);
                this_out_path
            },
            &raw_snapshot,
        )
        .map_err(|err| anyhow!("Error updating Rsync repository: {:?}", &err))?;
    Ok(())
}

//============ Tests =========================================================

#[cfg(test)]
#[test]
fn paths_are_appended() {
    let uri = uri::Rsync::from_string("rsync://rpki.example.org/repo/main.crl".into()).unwrap();

    assert_eq!(
        authority_module_rsync_repo_path(&uri),
        PathBuf::from_str("rpki.example.org/repo/main.crl")
    );
    assert_eq!(
        path_only_rsync_repo_path(&uri),
        PathBuf::from_str("main.crl")
    );
}
