use crate::http::Https;
use crate::lock;

use anyhow::{anyhow, Result};
use log::LevelFilter;
use structopt::clap::{arg_enum, crate_name, crate_version};
use structopt::StructOpt;

use std::path::{Path, PathBuf};

pub const DELTA_FNAME: &str = "delta.xml";
pub const NOTIFICATION_FNAME: &str = "notification.xml";
pub const REPORT_MAX: usize = 1;
pub const REPORT_PERCENTAGE: usize = 10;
pub const REPORT_MIN: usize = 200;
pub const SNAPSHOT_FNAME: &str = "snapshot.xml";
pub const TMP_FILE_EXT: &str = "tmp";
pub const OLD_FILE_EXT: &str = "old";
pub const USER_AGENT: &str = concat!(crate_name!(), "/", crate_version!());

/// The default number of seconds after we have published a snapshot or delta
/// that it becomes, if unreferenced, elligble for cleanup.
pub const DEFAULT_CLEANUP_SECONDS: &str = "600"; // 10 minutes

/// The default location to write our process ID to so that on invocation we can
/// check if we are already running. Cleared on boot according to the Linux FHS.
/// See: https://www.pathname.com/fhs/pub/fhs-2.3.html#VARRUNRUNTIMEVARIABLEDATA
pub const DEFAULT_PID_FILE_PATH: &str = concat!("/var/run/", crate_name!(), ".pid");

/// The default location in which to store RRDP repository files.
pub const DEFAULT_RRDP_DIR: &str = concat!("/var/lib/", crate_name!(), "/rrdp");

/// Time to wait with publishing a new RRDP notify after the snapshot and deltas
/// have been written.
pub const DEFAULT_RRDP_NOTIFY_DELAY_SECONDS: &str = "0";

/// The default location in which to store Rsync repository files.
pub const DEFAULT_RSYNC_DIR: &str = concat!("/var/lib/", crate_name!(), "/rsync");

/// The default location in which to store our state.
/// See: https://www.pathname.com/fhs/pub/fhs-2.3.html#VARLIBVARIABLESTATEINFORMATION
pub const DEFAULT_STATE_DIR: &str = concat!("/var/lib/", crate_name!());

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum Format {
        Both,
        Rrdp,
        Rsync
    }
}

impl Default for Format {
    fn default() -> Self {
        Format::Both
    }
}

trait Replace {
    fn replace(&self, from_str: &str, to: &Path) -> PathBuf;
}

impl Replace for PathBuf {
    fn replace(&self, from_str: &str, to: &Path) -> PathBuf {
        let to_str = format!("{}", to.display());
        let self_str = format!("{}", self.display());
        PathBuf::from(self_str.replace(&from_str, &to_str))
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = "A tool to synchronize an RRDP and/or Rsync server with a remote RRDP publication point.",
    long_version = concat!(crate_version!(), " (", env!("VERGEN_SHA_SHORT"), ")"),
)]
pub struct Opt {
    // The number of occurrences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(
        short = "v",
        long = "verbose",
        parse(from_occurrences),
        conflicts_with = "quiet"
    )]
    pub verbose: u8,

    /// Quiet mode (no warnings or informative messages, only errors)
    #[structopt(short = "q", long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,

    /// Disable delta replay (RRDP content will match the upstream exactly but syncing will be slower)
    #[structopt(long = "force-snapshot")]
    pub force_snapshot: bool,

    /// Force update even if the upstream RRDP notification file is unchanged
    #[structopt(long = "force-update")]
    pub force_update: bool,

    /// Output both RRDP and Rsync style repositories or only one of them?
    #[structopt(long = "format", short = "f", default_value, possible_values(&Format::variants()), case_insensitive = true )]
    pub format: Format,

    /// The location to write our process ID to
    #[structopt(long = "pid-file", parse(from_os_str), default_value = DEFAULT_PID_FILE_PATH)]
    pub pid_file: PathBuf,

    /// The directory to write state to
    #[structopt(long = "state-dir", short = "s", parse(from_os_str), default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,

    /// The directory to write RRDP files to
    #[structopt(long = "rrdp-dir", parse(from_os_str), default_value = DEFAULT_RRDP_DIR)]
    pub rrdp_dir: PathBuf,

    /// Delay seconds before writing the notification.xml file
    #[structopt(long = "rrdp-notify-delay", value_name = "seconds", default_value = DEFAULT_RRDP_NOTIFY_DELAY_SECONDS)]
    pub rrdp_notify_delay: u64,

    /// The directory to write Rsync files to
    #[structopt(long = "rsync-dir", parse(from_os_str), default_value = DEFAULT_RSYNC_DIR)]
    pub rsync_dir: PathBuf,

    /// The minimum number of seconds that a dangling snapshot or delta must have been published by krill-sync before it can be removed
    #[structopt(long = "cleanup-after", value_name = "seconds", default_value = DEFAULT_CLEANUP_SECONDS)]
    pub cleanup_after: i64,

    /// Whether or not localhost connections and self-signed certificates are
    /// allowed.
    #[structopt(long = "insecure")]
    pub insecure: bool,

    /// The RRDP notification file URI of the Krill instance to sync with
    pub notification_uri: Https,
}

fn log_without_target(
    out: fern::FormatCallback,
    message: &std::fmt::Arguments,
    record: &log::Record,
) {
    out.finish(format_args!(
        "{} {}: {}",
        chrono::Local::now().format("%Y/%m/%d %H:%M:%S"),
        record.level(),
        message,
    ))
}

fn log_with_target(out: fern::FormatCallback, message: &std::fmt::Arguments, record: &log::Record) {
    out.finish(format_args!(
        "{} {} [{}] {}",
        chrono::Local::now().format("%Y/%m/%d %H:%M:%S"),
        record.level(),
        record.target(),
        message,
    ))
}

pub fn configure() -> Result<Opt> {
    let mut opt = Opt::from_args();

    let (ks_log_level, other_log_level) = if opt.quiet {
        (LevelFilter::Error, LevelFilter::Error)
    } else {
        match opt.verbose {
            0 => (LevelFilter::Warn, LevelFilter::Warn),
            1 => (LevelFilter::Info, LevelFilter::Warn),
            2 => (LevelFilter::Debug, LevelFilter::Warn),
            3 => (LevelFilter::Trace, LevelFilter::Warn),
            4 => (LevelFilter::Trace, LevelFilter::Info),
            5 => (LevelFilter::Trace, LevelFilter::Debug),
            _ => (LevelFilter::Trace, LevelFilter::Trace),
        }
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            if ks_log_level <= LevelFilter::Debug {
                log_without_target(out, message, record)
            } else {
                log_with_target(out, message, record)
            }
        })
        .level(other_log_level)
        .level_for("krill_sync", ks_log_level)
        .chain(std::io::stdout())
        .apply()?;

    if let Err(err) = lock::lock(&opt.pid_file) {
        return Err(anyhow!(
            "Failed to create lock file {:?}: {} (tip: use --pid-file to \
            change the location of the lock file) ",
            &opt.pid_file,
            err
        ));
    }

    // Ensure the lock file is removed even if we are killed by SIGINT or SIGTERM
    let unlock_pid_file = opt.pid_file.clone();
    ctrlc::set_handler(move || {
        error!("CTRL-C caught, aborting.");
        lock::unlock(&unlock_pid_file).unwrap();
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler");

    // If --state-dir was changed from the default, ensure that --rrdp-dir and
    // --rsync-dir follow the change if their defaults were not overriden. This
    // is a bit more complicated than I would like but this way --help shows the
    // default values correctly without needing to specify them multiple times,
    // and with structopt I don't think I can get to the underlying clap matches
    // to find out if the args were specified (by checking the number of
    // occurences).
    if opt.state_dir != Path::new(DEFAULT_STATE_DIR) {
        if opt.rrdp_dir == Path::new(DEFAULT_RRDP_DIR) {
            opt.rrdp_dir = opt.rrdp_dir.replace(DEFAULT_STATE_DIR, &opt.state_dir);
        }
        if opt.rsync_dir == Path::new(DEFAULT_RSYNC_DIR) {
            opt.rsync_dir = opt.rsync_dir.replace(DEFAULT_STATE_DIR, &opt.state_dir);
        }
    }

    if opt.force_snapshot {
        info!("Note: --force-snapshot=true: Snapshot download has been forced. RRDP deltas will not be used to accelerate snapshot syncing.")
    }
    if opt.force_update {
        info!("Note: --force-update=true: Update will be forced even if upstream RRDP content is unchanged.")
    }

    Ok(opt)
}
