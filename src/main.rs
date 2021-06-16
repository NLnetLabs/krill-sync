use std::path::Path;

use anyhow::{Context, Result, anyhow};

use fslock::LockFile;
use krill_sync::{
    config::{configure, Config},
    file_ops::write_buf,
    process::process,
};

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
    if let Err(err) = lock(&config) {
        return Err(anyhow!(
            "Failed to create lock file {:?}: {} (tip: use --pid-file to \
            change the location of the lock file) ",
            &pid_file,
            err
        ));
    }

    let process_res = process(&config);
    if let Err(e) = unlock(&config.lock_file(), &config.pid_file) {
        eprint!("Failed to unlock: {}", e);
    }

    process_res
}

pub fn lock(config: &Config) -> Result<()> {
    let lock_file_path = config.lock_file();
    let mut lock_file = LockFile::open(&lock_file_path)?;

    lock_file.lock()
        .with_context(|| format!("Cannot lock using lockfile: {:?}", lock_file_path))?;
        
    write_buf(
        &config.pid_file,
        &format!("{}\n", std::process::id()).as_bytes().to_vec(),
    )?;
    
    // Ensure the lock file is removed even if we are killed by SIGINT or SIGTERM
    let pid_file = config.pid_file.to_owned();
    ctrlc::set_handler(move || {
        eprintln!("CTRL-C caught, aborting.");
        if let Err(e) = unlock(&lock_file_path, &pid_file) {
            eprintln!("Could remove lockfile and pid file: {}", e);
        }
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler");
    
    Ok(())
}

pub fn unlock(lock_file_path: &Path, pid_file: &Path) -> Result<()> {
    let mut lock_file = LockFile::open(lock_file_path)?;
    lock_file.unlock()
        .with_context(|| format!("Cannot unlock using lockfile: {:?}", lock_file_path))?;
    
    if pid_file.exists() {
        std::fs::remove_file(pid_file)
            .with_context(|| format!("Cannot remove pid file at {:?}", pid_file))?;
    }

    Ok(())
}