use anyhow::{anyhow, Context, Result};

use fslock::LockFile;
use krill_sync::{
    config::{configure, Config},
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
    // secure lock, note: will be unlocked when the LockFile goes out of scope.
    let _lock_file = lock(&config)?;
    process(&config)
}

fn lock(config: &Config) -> Result<LockFile> {
    if !config.state_dir.exists() {
        debug!(
            "State directory '{:?}' does not exist yet, will try to create it.",
            config.state_dir
        );
        std::fs::create_dir_all(&config.state_dir)
            .with_context(|| format!("Cannot create state directory: {:?}", config.state_dir))?;
    }

    let lock_file_path = config.lock_file();
    let mut lock_file = LockFile::open(&lock_file_path)
        .with_context(|| format!("Cannot open lockfile: {:?}", lock_file_path))?;

    if !lock_file
        .try_lock()
        .with_context(|| format!("Cannot lock using lockfile: {:?}", lock_file_path))?
    {
        Err(anyhow!(format!(
            "another krill-sync process holds the lock at {:?}",
            lock_file_path
        )))
    } else {
        Ok(lock_file)
    }
}
