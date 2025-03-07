use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use log::LevelFilter;
use structopt::clap::{crate_name, crate_version};
use structopt::StructOpt;

use rpki::uri::Https;

use crate::fetch::{FetchMap, FetchMode, FetchSource, Fetcher};

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
/// that it becomes, if unreferenced, eligible for cleanup.
pub const DEFAULT_CLEANUP_SECONDS: &str = "3600"; // 60 minutes

/// The default location to write our process ID.
///
/// Cleared on boot according to the Linux FHS.
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

trait Replace {
    fn replace(&self, from_str: &str, to: &Path) -> PathBuf;
}

impl Replace for PathBuf {
    fn replace(&self, from_str: &str, to: &Path) -> PathBuf {
        let to_str = format!("{}", to.display());
        let self_str = format!("{}", self.display());
        PathBuf::from(self_str.replace(from_str, &to_str))
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    about = "A tool to synchronize an RRDP and/or Rsync server with a remote RRDP publication point.",
)]
pub struct Config {
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

    /// The directory to write state to
    #[structopt(long = "state-dir", value_name = "dir", short = "s", parse(from_os_str), default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,

    /// The directory to write RRDP files to
    #[structopt(long = "rrdp-dir", value_name = "dir", parse(from_os_str), default_value = DEFAULT_RRDP_DIR)]
    pub rrdp_dir: PathBuf,

    /// Delay seconds before writing the notification.xml file
    #[structopt(long = "rrdp-notify-delay", value_name = "seconds", default_value = DEFAULT_RRDP_NOTIFY_DELAY_SECONDS)]
    pub rrdp_notify_delay: u64,

    /// Optional hard upper limit to the number of deltas
    #[structopt(long = "rrdp-max-deltas", value_name = "number")]
    pub rrdp_max_deltas: Option<usize>,

    /// The directory to write Rsync files to
    #[structopt(long = "rsync-dir", value_name = "dir", parse(from_os_str), default_value = DEFAULT_RSYNC_DIR)]
    pub rsync_dir: PathBuf,

    /// Force using directory moves rather than symlinks on unix systems. Added for unit testing this
    /// code path, not for giving this bad idea to users! So skip it for structopt.
    #[structopt(skip)]
    pub rsync_dir_force_moves: bool,

    /// Disable writing the rsync files.
    #[structopt(long = "rsync-disable")]
    pub rsync_disable: bool,

    /// Support different rsync base URIs, include host and module: <rsync_dir>/current/<host>/<module>/..
    #[structopt(long = "rsync-include-host")]
    pub rsync_include_host: bool,

    /// Remove unreferenced files and directories older than X seconds
    #[structopt(long = "cleanup-after", value_name = "seconds", default_value = DEFAULT_CLEANUP_SECONDS)]
    pub cleanup_after: i64,

    /// Whether or not localhost connections and self-signed certificates are allowed
    #[structopt(long = "insecure")]
    pub insecure: bool,

    /// The public RRDP notification URI
    pub notification_uri: Https,

    /// Slash terminated base uri for the notify file source
    #[structopt(
        long = "source-uri-base",
        alias = "source_uri_base",
        value_name = "uri"
    )]
    pub source_uri_base: Option<FetchSource>,

    #[structopt(skip)]
    pub fetch_map: Option<FetchMap>,

    // Validation support
    /// Optional TAL file(s) used to warn about, or reject, invalid content.
    /// NOTE: if you use this as the last option, be sure to add '--' to avoid
    /// that the <notification-uri> argument is interpreted as an additional
    /// TAL file location.
    #[structopt(long = "tal", value_name = "tal file", parse(from_os_str))]
    pub tal_files: Vec<PathBuf>,

    /// Optional external script(s) used to pre-validate the content of the
    /// repository before updating the target RRDP and rsync directories.
    #[structopt(long = "pre-validate", value_name = "script", parse(from_os_str))]
    pub pre_validation_scripts: Vec<PathBuf>,

    /// If true: reject if there are objects invalid under configured TAL(s)
    /// Note that this is limited to objects that are expected to be present and
    /// valid under the TAL(s). Other objects are not validated and are always
    /// accepted. Restrictions on this MUST NOT be enforced in krill-sync, and
    /// unfortunately cannot really be enforced in the Publication Server either.
    #[structopt(long = "tal-reject-invalid")]
    pub tal_reject_invalid: bool,

    /// If true: do not attempt to download any additional data from repositories
    /// other than the source repository that is being synced when doing validation.
    /// This may be particularly useful to speed up the validation process if the
    /// source repository is the repository that is being used by the (one) TAL
    /// used for validation. But note that the validation process will use cached data
    /// from the previous run, so this can also be useful for repositories for CAs
    /// further down in the tree.
    #[structopt(long = "offline-validation")]
    pub offline_validation: bool,
}

impl Config {
    pub fn rsync_enabled(&self) -> bool {
        !self.rsync_disable
    }

    pub fn rsync_dir_use_symlinks(&self) -> bool {
        if cfg!(unix) {
            !self.rsync_dir_force_moves
        } else {
            false
        }
    }

    pub fn rsync_dir_current(&self) -> PathBuf {
        self.rsync_dir.join("current")
    }

    pub fn fetcher(&self) -> Fetcher {
        let mode = if self.insecure {
            FetchMode::Insecure
        } else {
            FetchMode::Strict
        };

        Fetcher::new(self.notification_uri.clone(), self.fetch_map.clone(), mode)
    }

    pub fn staging_path(&self, relative: &str) -> PathBuf {
        self.state_dir.join("pre-validate-staging").join(relative)
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.state_dir.join("pre-validate-staging")
    }

    pub fn rrdp_state_path(&self) -> PathBuf {
        self.state_dir.join("rrdp-state.json")
    }

    pub fn rsync_state_path(&self) -> PathBuf {
        self.state_dir.join("rsync-state.json")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("krill-sync.lock")
    }
}

pub fn configure() -> Result<Config> {
    let config = Config::from_args();
    post_configure(config)
}

#[cfg(test)]
pub fn create_test_config(
    work_dir: &Path,
    notification_uri: Https,
    source_uri_base: &str,
    rsync_dir_force_moves: bool,
) -> Config {
    let source_uri_base = FetchSource::File(PathBuf::from(source_uri_base));

    let state_dir = work_dir.join("state");
    let rrdp_dir = work_dir.join("rrdp");
    let rsync_dir = work_dir.join("rsync");

    let config = Config {
        verbose: 0,
        quiet: false,
        state_dir,
        rrdp_dir,
        rrdp_notify_delay: 0,
        rrdp_max_deltas: Some(3),
        rsync_dir,
        rsync_dir_force_moves,
        rsync_disable: false,
        rsync_include_host: false,
        cleanup_after: 2,
        insecure: false,
        notification_uri,
        source_uri_base: Some(source_uri_base),
        fetch_map: None, // will be set in post_configure
        tal_files: vec![],
        pre_validation_scripts: vec![],
        tal_reject_invalid: false,
        offline_validation: true,
    };
    post_configure(config).unwrap()
}

pub fn post_configure(mut config: Config) -> Result<Config> {
    initialize_logging(&config);

    let base_uri = config
        .notification_uri
        .parent()
        .ok_or_else(|| anyhow!("Notification URI should contain a path to a file"))?;

    // If a source_uri_base was specified together with --insecure,
    // then we will need update the default 'strict' config. This is
    // needed because the source map uses FromStr and is only aware
    // of the URI / disk path.
    if config.insecure {
        let source_uri_base_opt = config.source_uri_base.take();

        if let Some(source_uri_base) = source_uri_base_opt {
            let source_uri_base = match source_uri_base {
                FetchSource::File(file) => FetchSource::File(file),
                FetchSource::Uri(uri, _) => FetchSource::Uri(uri, FetchMode::Insecure),
            };

            config.source_uri_base.replace(source_uri_base);
        }
    }

    if let Some(base_fetch) = config.source_uri_base.as_ref() {
        if !base_fetch.is_dir() {
            return Err(anyhow!(
                "source_uri_dir is not a readable dir or base path ending in a slash"
            ));
        } else {
            config.fetch_map = Some(FetchMap::new(base_uri, base_fetch.clone()))
        }
    }

    // If --state-dir was changed from the default, ensure that --rrdp-dir and
    // --rsync-dir follow the change if their defaults were not overridden. This
    // is a bit more complicated than I would like but this way --help shows the
    // default values correctly without needing to specify them multiple times,
    // and with structopt I don't think I can get to the underlying clap matches
    // to find out if the args were specified (by checking the number of
    // occurrences).
    if config.state_dir != Path::new(DEFAULT_STATE_DIR) {
        if config.rrdp_dir == Path::new(DEFAULT_RRDP_DIR) {
            config.rrdp_dir = config
                .rrdp_dir
                .replace(DEFAULT_STATE_DIR, &config.state_dir);
        }
        if config.rsync_dir == Path::new(DEFAULT_RSYNC_DIR) {
            config.rsync_dir = config
                .rsync_dir
                .replace(DEFAULT_STATE_DIR, &config.state_dir);
        }
    }

    Ok(config)
}

fn initialize_logging(config: &Config) {
    let (ks_log_level, other_log_level) = if config.quiet {
        (LevelFilter::Error, LevelFilter::Error)
    } else {
        match config.verbose {
            0 => (LevelFilter::Warn, LevelFilter::Warn),
            1 => (LevelFilter::Info, LevelFilter::Warn),
            2 => (LevelFilter::Debug, LevelFilter::Warn),
            3 => (LevelFilter::Trace, LevelFilter::Warn),
            4 => (LevelFilter::Trace, LevelFilter::Info),
            5 => (LevelFilter::Trace, LevelFilter::Debug),
            _ => (LevelFilter::Trace, LevelFilter::Trace),
        }
    };

    // ignore the result - this will only fail if logging was already initialized,
    // and that may happen when running tests in parallel.
    let _ = fern::Dispatch::new()
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
        .apply();
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
