# krill-sync

An *experimental* tool to synchronize an RRDP and/or Rsync server with a "hidden" remote [RFC 8182](https://tools.ietf.org/html/rfc8182) RRDP publication point. _**Note:** currently only tested with and makes assumptions specific to [Krill](https://nlnetlabs.nl/projects/rpki/krill/)._

## TL;DR

For Ubuntu 20.04:

```
$ apt update && apt install -y build-essential curl libssl-dev openssl pkg-config
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ cargo install --git https://github.com/NLnetLabs/krill-sync.git --tag v0.1.0
$ krill-sync https://<hidden fqdn of RRDP publication point>/rrdp/notification.xml -v
...
```

**Tada!** Rsync and RRDP directories have now been created locally which can be used to serve the content produced by the remote "hidden" RRDP origin server via the RRDP and Rsync protocols. Note: this tool does not serve them for you, for that you need NGINX and Rsyncd for example.

## Introduction

This tool is intended to enable public facing RRDP and Rsync servers to serve consistent and fresh content obtained from a "hidden" RRDP master server, e.g. that runs a Krill RPKI Certificate Authority and RPKI publication repository. In this context "hidden" means that the server is not reachable by the public name of the repository but creates content that points to the public name. Krill Sync is smart enough to know that it shouldn't blindly follow FQDNs in the RRDP content to download snapshots and deltas but instead goes to the specified "hidden" FQDN each time instead.

![Sequence Diagram](http://www.plantuml.com/plantuml/png/lPFVJzim4CVV_LUS-aGbYBGVJsYTg6WH4LE9qg9fKrzCVANMd7DcNu3yztCSGiOYDFgmlJJk-NFVEtzzFlCi7TUb4LNuwa9NaXWcEPf6qnra8TXCG7h8ivV4njMUOKx5the8RERYrZx-ALDPhzcw1jRexj4T-McdjiokNw9NJXi3wuQA25ojlwtE1PA2aUYbLWe9Hjenxp9TB9Oh8MOpI5Vf9fr_IR_FD-dr2cOp8Q8gd7n-mauXpnSPa6MzquLaRGbssY0u_5cZvoV-qybV-44tBWA63qupWYTP-RrbaAH0eM49DtdgN-aZ0YyQy4C7hv23LlJq5Bx6mhaFHWQLoW9RKDh_U8KBQgCkU-atf8wjwtFoh4tOp4zXeNrXm_r0dbsbu8Phy_7QmDWktuUSSDAG4nP3jHlV7yUwhYXRs24N-otz9bPOOYJkHUA09KaI9o5Rvkdr8ZqFqOjykRuyQ1Q2iDBjNsaEdGiuqZiezfBkK4s5a8OX10WVncXhXWuLg2vlqO7s8E-bDlBMeFXtumKxws8_SS-39TCSC79zF_EgCaslmHRkaD19HgWh5JxgkT4j7Tcgy_8O2acWoJDArTrdxAH7fwCg5_fnEF5U-dqmSmWyIFzSLxtrKS14iYrr8Orf9iUW4qosz2w1pbuE79RLbjud8OjaYL3KBgoutR96RUb3lnF94Ew9BNrCMaUGiIMd__7vZGuc198IP-6dBiql)

## Rationale

Using the RRDP protocol ensures that only complete and consistent data is downloaded by following the Notification File to the dependent resources (assuming a publication server such as Krill that ensures that the Notification File is written last during a content update). It also enables the public servers to download only deltas rather than the entire snapshot on update keeping the sync time, bandwidth usage and origin server impact to a minimum.

Other means of synchronizing the content (e.g. rsync, scp, or possibly even file system replication tools like GlusterFS) are not RRDP aware and thus may sync the Notification File before the files it references have all been downloaded which can cause Relying Party clients of the public facing repository servers to encounter errors while attempting to download updates from the service.

By default directory content for serving by an Rsync daemon is also created from the data downloaded via RRDP, no `rsync` binary is needed.

## Usage

This tool is intended to be used as a system "service" invoked periodically e.g. once a minute from cron, it is not meant to be a user facing tool. As such it follows [Linux FHS](https://refspecs.linuxfoundation.org/fhs.shtml) guidelines for storing application state rather than user state.

The simplest use case (assuming that the invoking user has write access to the default directories, see below) requires only the URL where the RFC 8182 RRDP Notification File can be downloaded, e.g.:

```
# krill-sync https://some.server/rrdp/notification.xml
```

On first run this will download the complete set of RRDP snapshot and delta files from the remote server and store them locally, e.g. for serving by NGINX or some other HTTP server.

On a subsequent run where no new data is available no changes will be made, with the possible exception of deletion of no longer referenced snapshot and delta files.

If new data is available the RRDP deltas will be used to update the local RRDP snapshot and delta files and then the Rsync files.

The Notification File is always written to disk last.

## Advanced Usage

If needed the directories in which internal state and repository output are stored can be specified, and for servers that serve only RRDP or Rsync but not both it the output can be constrained to just the required format _(though the protocol used between krill-sync and the upstream RRDP server is always RRDP)_.

```
$ krill-sync --help
krill-sync 0.1.0
A tool to synchronize an RRDP and/or Rsync server with a remote RRDP publication point.

USAGE:
    krill-sync [FLAGS] [OPTIONS] <notification-uri>

FLAGS:
        --force-snapshot    Disable delta replay (RRDP content will match the upstream exactly but syncing will be
                            slower)
        --force-update      Force update even if the upstream RRDP notification file is unchanged
    -h, --help              Prints help information
        --insecure          Whether or not localhost connections and self-signed certificates are allowed
    -q, --quiet             Quiet mode (no warnings or informative messages, only errors)
    -V, --version           Prints version information
    -v, --verbose           Verbose mode (-v, -vv, -vvv, etc.)

OPTIONS:
        --cleanup-after <seconds>    The minimum number of seconds that a dangling snapshot or delta must have been
                                     published by krill-sync before it can be removed [default: 600]
    -f, --format <format>            Output both RRDP and Rsync style repositories or only one of them? [default: BOTH]
                                     [possible values: BOTH, RRDP, RSYNC]
        --pid-file <pid-file>        The location to write our process ID to [default: /var/run/krill-sync.pid]
        --rrdp-dir <rrdp-dir>        The directory to write RRDP files to [default: /var/lib/krill-sync/rrdp]
        --rsync-dir <rsync-dir>      The directory to write Rsync files to [default: /var/lib/krill-sync/rsync]
    -s, --state-dir <state-dir>      The directory to write state to [default: /var/lib/krill-sync]

ARGS:
    <notification-uri>    The RRDP notification file URI of the Krill instance to sync with
```

_**Tip:** Unlike the `-V` argument, the `--version` argument also prints out the Git commit from which krill-sync was built._

_**Tip:** If connecting directly to a Krill server, and not to e.g. NGINX in front of Krill, you will need to use `--insecure` as the Krill RRDP service uses a self-signed TLS certificate._

## Log filtering

By default krill-sync will output only warnings and errors. Using `-v` or `--verbose` repeatedly will cause krill-sync to print more and more detailed information about its activity. The first three levels enable info, debug and trace logging for krill-sync itself. The three levels after that enable info, debug and trace logging for 3rd party Rust crates that krill-sync uses.

## Implementation

The tool is a work in progress. It uses the NLnet Labs Routinator 3000 library with minor modifications to support [RFC 7232](https://tools.ietf.org/html/rfc7232) conditional requests (only ETags at the time of writing, and only for the Notification File) and to permit self-signed RRDP server TLS certificates.

A number of 3rd party Rust crates are used for argument parsing, logging, base64 and sha256, JSON (de)serialization, directory traversal and easy parallelisation support. The latter is used to easily support parallel download of RRDP delta files from large repositories (e.g. >1000 deltas), using upto as many CPU cores as are available to download in parallel.

The current implementation makes a number of assumptions that are Krill specific, e.g. it contains hard-coded references to `notification.xml` and assumed that deltas are stored at `<session id>/<delta serial number>/delta.xml`, but there are RRDP servers that refer to `notify.xml` and that serve deltas at `<session id>/deltas/<delta serial number>.xml` for example.
