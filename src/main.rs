use std::path::Path;

use anyhow::{anyhow, Context, Result};

use fslock::LockFile;
use krill_sync::{
    config::{configure, Config},
    file_ops::write_buf,
    process::process,
};
use log::debug;

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
    let mut lock_file = lock(&config)?;
    write_pid_file(&config.pid_file)?;

    let process_res = process(&config);

    lock_file.unlock().with_context(|| "Could not remove lockfile")?;
    remove_pid_file(&config.pid_file)?;

    process_res
}

fn lock(config: &Config) -> Result<LockFile> {
    if !config.state_dir.exists() {
        debug!("State directory '{:?}' does not exist yet, will try to create it.", config.state_dir);
        std::fs::create_dir_all(&config.state_dir)
            .with_context(|| format!("Cannot create state directory: {:?}", config.state_dir))?;
    }

    let lock_file_path = config.lock_file();
    let mut lock_file = LockFile::open(&lock_file_path)
        .with_context(|| format!("Cannot open lockfile: {:?}", lock_file_path))?;
    
    if !lock_file.try_lock()
        .with_context(|| format!("Cannot lock using lockfile: {:?}", lock_file_path))?
    {
        Err(anyhow!(format!("another krill-sync process holds the lock at {:?}", lock_file_path)))
    } else {
        Ok(lock_file)
    }
}

fn write_pid_file(pid_file: &Path) -> Result<()> {
    write_buf(
        pid_file,
        &format!("{}\n", std::process::id()).as_bytes().to_vec(),
    ).with_context(|| format!("Cannot create pid file: {:?}, (tip use --pid_file to change the location).", pid_file))?;
    
    // Ensure the pid file is removed even if we are killed by SIGINT or SIGTERM
    let pid_file = pid_file.to_owned();
    ctrlc::set_handler(move || {
        eprintln!("CTRL-C caught, aborting.");
        if let Err(e) = remove_pid_file(&pid_file) {
            eprintln!("Could remove pid file: {}", e);
        }
        std::process::exit(1);
    }).expect("Error setting Ctrl-C handler");

    Ok(())
}


fn remove_pid_file(pid_file: &Path) -> Result<()> {
    if pid_file.exists() {
        std::fs::remove_file(pid_file)
            .with_context(|| format!("Cannot remove pid file at {:?}", pid_file))?;
    }

    Ok(())
}