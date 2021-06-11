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