# krill-sync

This tool uses the RRDP data from a (single) "hidden" backend RPKI Publication
Server to make a consistent local copy of that data.

This is intended to facilitate a redundant set up where one or more public https
and rsync servers are used to make the RPKI repository content available.


## Installation

### Install using Pre-built Packages

Assuming you have a machine running a recent Debian or Ubuntu distribution, you 
can install krill-sync from our [software package repository](https://packages.nlnetlabs.nl).
To use this repository, add the line below that corresponds to your operating system to 
your `/etc/apt/sources.list` or `/etc/apt/sources.list.d/`

```bash
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ buster main
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ bullseye main
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ bookworm main
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ focal main
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ jammy main
deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ noble main
```
Then run the following commands.

```bash
wget -qO- https://packages.nlnetlabs.nl/aptkey.asc | sudo apt-key add -
sudo apt update
```

You can then install krill-sync by running

```bash
sudo apt install krill-sync
```


### Build with Cargo

For Ubuntu 24.04 with Rust 1.86.0:

```
apt update && apt install -y build-essential curl libssl-dev openssl pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo install --git https://github.com/NLnetLabs/krill-sync.git --tag v0.3.0-rc1 --locked
```

## Introduction

This tool is intended to enable public facing RRDP and Rsync servers to serve consistent
and fresh content obtained from a "hidden" RRDP source server, e.g. that runs an 
RPKI Publication Server. In this context "hidden" means that the server is not reachable
by the public name of the repository but creates content that points to the public name.

## Data Retrieval and Assumptions

The repository data is retrieved by using the RRDP protocol itself, pointed at a hidden
back-end server. `krill-sync` (as of 0.2.x) assumes that the back-end publication server
uses the intended public URIs for its RRDP files. But, importantly, we can instruct it to
map the URI of a given public RRDP notification URI to an alternative hidden backend server:

```
krill-sync --source_uri_base https://hidden.server/rrdp/ https://some.server/rrdp/notification.xml
```

There is a further assumption that snapshot and delta file URIs will use the same hostname
and base path as the notification file, so that it can be resolved to the back-end using the
same `--source_uri_base` map that is used for the notification file itself.

Using the RRDP protocol as a source ensures that only complete and consistent data is downloaded
by following the Notification File to the dependent resources (assuming a publication server
such as Krill that ensures that the Notification File is written last during a content
update). It also enables the public servers to download only deltas rather than the entire
snapshot on update keeping the sync time, bandwidth usage and origin server impact to a minimum.

Other means of synchronizing the content (e.g. rsync, scp, or possibly even file system
replication tools like GlusterFS) are not RRDP aware and thus may sync the Notification File
before the files it references have all been downloaded which can cause Relying Party clients
of the public facing repository servers to encounter errors while attempting to download updates
from the service.

## Synchronization

When `krill-sync` runs without previous state, it will retrieve and parse the specified
notification file. Then it will retrieve and parse the snapshot file to obtain all current
objects, as well as each delta file mentioned (unless an optional hard limit is set, see below).

If a file cannot be retrieved or **parsed** then the run will fail. This means that if the
back-end system RFC 8182 RRDP XML is somehow not understood by krill-sync the data will
not be accepted.

The tool will persist its current state to disk. The default directory for this is
`/var/lib/krill-sync` but this can be overridden using the `--state-dir` argument.

On subsequent runs `krill-sync` will check whether delta files can be used to update its
current state. I.e. the session is unchanged and there is a chain of delta files
available. If not, it will re-sync using the current back-end snapshot.

We recommend that you run krill-sync at least every 5 minutes from cron, but every
minute should be fine too. Make sure that errors are reported back to you, e.g.
by having cron email them. Note that a krill-sync invocation will abort with an error
message if it finds that another instance (previous invocation) is still running.
In that case you may have to reduce the frequency. That said, we found that on
reasonably fast hardware a clean krill-sync takes less than a minute even for huge
repositories, and subsequent updates are even faster.

## Produced RRDP Data

This tool produces its own RRDP data XML. This means that the formatting, hash values
and even the URI paths of the RRDP files produced by this tool may be **different**
from the back-end. This is not issue as long as all your public facing RRDP front-ends
use `krill-sync`.

The RRDP files are written in a safe order, meaning: new snapshot and delta files are
written to disk first. Then a new notification file is written to a temporary file,
which is then renamed to avoid avoid race conditions resulting from overwriting this
file as it's being served.

Old snapshot and delta files are marked as 'deprecated' as soon they are no longer referenced
by the current notification file. Files which have been deprecated for longer than N seconds
are removed at the end of each synchronization. The default is 600 seconds, or 10
minutes, but note that this can be configured, and that the clean up only happens
when an actual synchronization is done.

The default base directory for these files is `/var/lib/krill-sync/rrdp/`, but this
can be overridden using the `--rrdp-dir` argument. The notification file will be
called `notification.xml` and will be published directly under this base directory.
Snapshot files are called `snapshot.xml`, delta files `delta.xml`. Snapshot and
delta files are stored under two further directories based on the session ID, which
is a UUID, and the serial.

Example of a resulting structure:
```
/var/lib/krill-sync/rrdp/notification.xml
/var/lib/krill-sync/rrdp/de3b0c3c-85be-45f8-b89c-5d4a0fa66312/305278/snapshot.xml
/var/lib/krill-sync/rrdp/de3b0c3c-85be-45f8-b89c-5d4a0fa66312/305278/delta.xml
/var/lib/krill-sync/rrdp/de3b0c3c-85be-45f8-b89c-5d4a0fa66312/305277/delta.xml
/var/lib/krill-sync/rrdp/de3b0c3c-85be-45f8-b89c-5d4a0fa66312/305276/delta.xml
```

Make sure that you map the base directory in your HTTPS front-end server, such
as NGINX, to this base directory in a way that the given public RRDP notification URI
will map to the file on disk.

## Rsync Data

Directory content for serving by an Rsync daemon is also created from the data downloaded
via RRDP, no `rsync` binary is needed. If you do not need to serve the rsync content on
a specific machine, then you can suppress this by using the `--disable-rsync` option.

This tool writes complete new rsync directories for each new RRDP session and serial that
is retrieved. On UNIX like systems symlinks are then used to link the `current` directory to
the latest content. As it turns out the rsync daemon resolves symlinks whenever a client
connects, so ongoing connections will keep being served the directory which was current
at the time of connection.

The previous directory is marked as deprecated whenever a new current directory is
created this way. At the end of each synchronization directories which have been
deprecated for more than N seconds (default 10 mins) are removed.

By default the base directory for these rsync directories is `/var/lib/krill-sync/rsync/`,
but this can be overridden using the `--rsync-dir` argument. Your `rsyncd` process
should be configured to serve the `current` directory, e.g.:

```
$ cat /etc/rsyncd.conf
uid = nobody
gid = nogroup
max connections = 50
socket options = SO_KEEPALIVE

[repo] ## <-- Use your public rsync module name here!
path = /var/lib/krill-sync/rsync/current/
comment = RPKI repository
read only = yes
```


## CLI Usage

This tool is intended to be used as a system "service" invoked periodically e.g. once
a minute from cron, it is not meant to be a user facing tool. As such it follows
[Linux FHS](https://refspecs.linuxfoundation.org/fhs.shtml) guidelines for storing
application state rather than user state.

```
krill-sync --help
krill-sync 0.2.2
A tool to synchronize an RRDP and/or Rsync server with a remote RRDP publication point.

USAGE:
    krill-sync [FLAGS] [OPTIONS] <notification-uri>

FLAGS:
    -h, --help                  Prints help information
        --insecure              Whether or not localhost connections and self-signed certificates are allowed
    -q, --quiet                 Quiet mode (no warnings or informative messages, only errors)
        --rsync-disable         Disable writing the rsync files
        --rsync-include-host    Support different rsync base URIs, include host and module:
                                <rsync_dir>/current/<host>/<module>/..
        --tal-reject-invalid    If true: reject if there are objects invalid under configured TAL(s) Note that this is
                                limited to objects that are expected to be present and valid under the TAL(s). Other
                                objects are not validated and are always accepted. Restrictions on this MUST NOT be
                                enforced in krill-sync, and unfortunately cannot really be enforced in the Publication
                                Server either
    -V, --version               Prints version information
    -v, --verbose               Verbose mode (-v, -vv, -vvv, etc.)

OPTIONS:
        --cleanup-after <seconds>        Remove unreferenced files and directories older than X seconds [default: 3600]
        --rrdp-dir <dir>                 The directory to write RRDP files to [default: /var/lib/krill-sync/rrdp]
        --rrdp-max-deltas <number>       Optional hard upper limit to the number of deltas
        --rrdp-notify-delay <seconds>    Delay seconds before writing the notification.xml file [default: 0]
        --rsync-dir <dir>                The directory to write Rsync files to [default: /var/lib/krill-sync/rsync]
        --source_uri_base <uri>          Slash terminated base uri for the notify file source
    -s, --state-dir <dir>                The directory to write state to [default: /var/lib/krill-sync]
        --tal <tal file>...              Optional TAL file(s) used to warn about, or reject, invalid content. NOTE: if
                                         you use this as the last option, be sure to add '--' to avoid that the
                                         <notification-uri> argument is interpreted as an additional TAL file location

ARGS:
    <notification-uri>    The public RRDP notification URI
```

_**Tip:** If connecting directly to a Krill server, and not to e.g. NGINX in front of Krill, you will need to use `--insecure` as the Krill RRDP service uses a self-signed TLS certificate._

## Log filtering

By default krill-sync will output only warnings and errors. Using `-v` or `--verbose` repeatedly will cause krill-sync to print more and more detailed information about its activity. The first three levels enable info, debug and trace logging for krill-sync itself. The three levels after that enable info, debug and trace logging for 3rd party Rust crates that krill-sync uses.

