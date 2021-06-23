# Use the same alpine image for both build stages
ARG BASE_IMG=alpine:3.14

#
# -- stage 1: build krill-sync
#
FROM ${BASE_IMG} AS build

RUN apk add rust cargo openssl-dev

WORKDIR /tmp/krill_sync
COPY . .

RUN cargo build --target x86_64-alpine-linux-musl --release --locked

#
# -- stage 2: create an image containing just the binaries, configs &
#             scripts needed to run Krill, and not the things needed to build
#             it.
#
FROM ${BASE_IMG}
COPY --from=build /tmp/krill_sync/target/x86_64-alpine-linux-musl/release/krill-sync /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=krill_sync
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

RUN apk add bash libgcc openssl tzdata util-linux

RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the data directories and create a volume mount point for them
# Note: If you map a host path to /data, e.g. with docker run -v /tmp/krill:/data, krill-sync will NOT be able to write
# to it unles you run first give the krill-sync user ownership of the directory on the host, e.g. like this:
#   mkdir /tmp/krill && sudo chown 1012 /tmp/krill 

RUN mkdir -p /data/ && \
    chown -R ${RUN_USER_UID}:${RUN_USER_GID} /data
VOLUME /data

# Trick krill-sync into writing into the mounted volume location so that users that want the state to be stored outside
# the container are not forced to specify -s /data when running krill-sync via this Docker image. Combined with the
# chown above this also ensures that krill-sync is able to write its lock file without a permission denied error.
# krill-sync is able 
WORKDIR /var/lib
RUN ln -s /data krill-sync

# Use Tini to ensure that krill-sync responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
RUN apk add --no-cache tini

# Run as ${RUN_USER} - not root
USER ${RUN_USER}
# Tini is now available at /sbin/tini
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/krill-sync"]