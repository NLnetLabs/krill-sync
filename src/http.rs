use crate::config;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rayon::prelude::*;
use rayon::current_num_threads;
use retry::{retry_with_index, delay::{Exponential, jitter}};
use ring::digest;
use routinator::reqwest::blocking::Response;
use routinator::rpki::rrdp::DigestHex;
use routinator::Config as RoutinatorConfig;

use std::cmp::{min, max};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::path::{Path, PathBuf};

pub use routinator::rpki::uri::Https;
pub use routinator::rrdp::http::HttpClient as HttpClient;

fn download(
    uri: &Https,
    client: &HttpClient,
    etag: Option<String>) -> Result<Option<Response>>
{
    debug!("Downloading {}", &uri);
    let response = client.response(&uri, etag).map_err(|error| anyhow!("Downloading {}: {:?}", &uri, error))?;
    match response.status().as_u16() {
        200 => Ok(Some(response)),
        304 => Ok(None), // Not Modified (i.e. ETag matched)
        other => Err(anyhow!("Error downloading {}: unexpected HTTP status code {}", &uri, other)),
    }
}

struct DigestWrite<W> {
    writer: W,
    context: digest::Context,
    expected_hash: Option<DigestHex>,
}

impl<W> DigestWrite<W> {
    fn new(writer: W, expected_hash: Option<DigestHex>) -> Self
    where
        W: std::io::Write
    {
        DigestWrite {
            writer,
            context: digest::Context::new(&digest::SHA256),
            expected_hash,
        }
    }

    pub fn verify(self) -> Result<()> {
        if let Some(expected_hash) = self.expected_hash {
            let digest = self.context.finish();
            #[allow(clippy::match_bool)]
            match digest.as_ref() == expected_hash.as_ref() {
                true  => Ok(()),
                false => Err(anyhow!("Hash mismatch")),
            }
        } else {
            Ok(())
        }
    }
}

impl<W: std::io::Write> std::io::Write for DigestWrite<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.context.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}

fn verified_copy_to<W: std::io::Write>(response: &mut Response, w: &mut W, expected_hash: Option<DigestHex>) -> Result<()> {
    let mut writer = DigestWrite::new(w, expected_hash);
    response.copy_to(&mut writer)?;
    writer.verify()
}

pub struct DownloadResult {
    pub body: Vec<u8>,
    pub etag: Option<String>,
}

// TODO: split this out into two functions, one that supports ETags and one
// that does not. This will simplify the error/result handling.
pub fn download_to_buf(
    uri: &Https,
    client: &HttpClient,
    send_etag: Option<String>,
    hash: Option<DigestHex>) -> Result<Option<DownloadResult>> {
    match download(uri, client, send_etag.clone())? {
        Some(mut response) => {
            let response_etag = response.headers().get("ETag");
            let possible_response_etag = response_etag.map(|v| v.to_str().unwrap().to_string());
            let mut buf: Vec<u8> = vec![];
            // response.copy_to(&mut buf)?;
            verified_copy_to(&mut response, &mut buf, hash)?;
            Ok(Some(DownloadResult {
                body: buf, 
                etag: possible_response_etag
            }))
        },
        None => match send_etag {
            Some(_) => Ok(None),
            None => unreachable!() // only when using an ETag is a successful no-response possible
        }
    }
}

pub fn download_to_file(
    uri: &Https,
    client: &HttpClient,
    send_etag: Option<String>,
    hash: Option<DigestHex>,
    file_path: &Path) -> Result<()> {
    match download(uri, client, send_etag) {
        Ok(Some(mut response)) => {
            match file_path.parent().ok_or_else(|| anyhow!("Error determining parent of {:?}", &file_path)) {
                Ok(dir) => {
                    std::fs::create_dir_all(&dir)?;
                    let mut f = std::fs::File::create(file_path)?;
                    // response.copy_to(&mut f)?;
                    verified_copy_to(&mut response, &mut f, hash)?;
                    Ok(())
                },
                Err(err) => Err(err)
            }
        },
        Ok(None) => Ok(()),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
pub enum DownloadType {
    ToFile((Https, Option<DigestHex>, PathBuf)),
    ToBuf(Https, Option<DigestHex>),
}

#[derive(Debug)]
pub enum MultiDownloadResult {
    ToFile(PathBuf),
    ToBuf(Vec<u8>),
}

pub fn download_multiple(
    files_to_download: &[DownloadType],
    client: &HttpClient) -> Result<DashMap<Https, MultiDownloadResult>>
{
    let num_downloads = files_to_download.len();
    let results = DashMap::with_capacity(num_downloads);

    if num_downloads > 0 {
        info!("Downloading {} files", num_downloads);

        let remaining = Arc::new(AtomicUsize::new(num_downloads));
        let remaining_ref = remaining.clone();
        let retries = Arc::new(AtomicUsize::new(0));
        let retries_ref = retries.clone();
        let failures = Arc::new(AtomicUsize::new(0));
        let failures_ref = failures.clone();

        let reporting_thread = std::thread::spawn(move || {
            trace!("Download report background thread started");
            let report_interval = max(config::REPORT_MAX,
                min(config::REPORT_MIN, (num_downloads / 100) * config::REPORT_PERCENTAGE));

            let mut n_when_last_reported = num_downloads;
            loop {
                let n_now = remaining_ref.load(Ordering::Relaxed);
                let n_retries = retries_ref.load(Ordering::Relaxed);
                let n_failures = failures_ref.load(Ordering::Relaxed);
                if n_now == 0 {
                    break;
                }
                let n_diff = n_when_last_reported - n_now;
                if n_diff >= report_interval {
                    info!("Downloading {} files concurrently: {} remaining, {} retried, {} failed",
                        current_num_threads(), n_now, n_retries, n_failures);
                    n_when_last_reported = n_now;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            trace!("Download report background thread exiting");
        });

        fn try_download(
            downloadable: &DownloadType,
            client: &HttpClient,
            results: &DashMap<Https, MultiDownloadResult>) -> Result<()>
        {
            match downloadable {
                DownloadType::ToFile((uri, hash, path)) => {
                    trace!("Downloading {:?} to file", downloadable);
                    download_to_file(&uri, &client, None, hash.clone(), &path)?;
                    trace!("Downloading {:?} to file finished", downloadable);
                    results.insert(uri.clone(), MultiDownloadResult::ToFile(path.clone()));
                    trace!("Downloading {:?} result inserted", downloadable);
                },
                DownloadType::ToBuf(uri, hash) => {
                    trace!("Downloading {:?} to buf", downloadable);
                    if let Some(result) = download_to_buf(uri, client, None, hash.clone())? {
                        trace!("Downloading {:?} to buf finished", downloadable);
                        results.insert(uri.clone(), MultiDownloadResult::ToBuf(result.body));
                        trace!("Downloading {:?} result inserted", downloadable);
                    }
                }
            };
            trace!("Downloading {:?} done", downloadable);
            Ok(())
        }

        files_to_download.par_iter().for_each(|downloadable| {
            if let Err(err) = retry_with_index(Exponential::from_millis(1000).map(jitter).take(3), |current_try| {
                trace!("Try {} for {:?}", current_try, downloadable);
                if current_try > 1 {
                    let _ = retries.fetch_add(1, Ordering::Relaxed);
                }
                try_download(downloadable, client, &results)
            }) {
                let uri = match downloadable {
                    DownloadType::ToFile((uri, ..)) => uri,
                    DownloadType::ToBuf(uri, ..) => uri,
                };
                error!("Failed to download {}: {:?}", uri, err);
                failures.fetch_add(1, Ordering::Relaxed);
            }

            trace!("Download attempts for {:?} complete", downloadable);
            let _ = remaining.fetch_sub(1, Ordering::Relaxed);
        });

        reporting_thread.join().unwrap();
        trace!("Download report background thread finished");

        if failures.load(Ordering::Relaxed) > 0 {
            return Err(anyhow!("One or more downloads failed"));
        }
    }

    Ok(results)
}

pub fn create_client(insecure: bool) -> HttpClient {
    let mut config = RoutinatorConfig::default();
    config.rrdp_user_agent = config::USER_AGENT.to_string();
    let mut rrdp_http_client = HttpClient::new(&config, insecure)
        .expect("Failed to create RRDP client");
    rrdp_http_client.ignite().expect("Failed to ignite RRDP client");
    rrdp_http_client
}
