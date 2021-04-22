# Use the same alpine image for both build stages
ARG BASE_IMG=alpine:3.13

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

# Create the data directories and create a volume for them
VOLUME /data
RUN mkdir -p /data/state /datarsync /data/rrdp && \
    chown -R ${RUN_USER_UID}:${RUN_USER_GID} /data

# Install a Docker entrypoint script that will be executed when the container
# runs
COPY docker/entrypoint.sh /opt/
RUN chown ${RUN_USER_UID}:${RUN_USER_GID} /opt/entrypoint.sh

# Set default, non-existend rrdp url
ENV RRDP_URL="https://localhost/notification.xml"

WORKDIR /tmp

# Use Tini to ensure that krill-sync responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
RUN apk add --no-cache tini

# Run as ${RUN_USER} - not root
USER ${RUN_USER}
# Tini is now available at /sbin/tini
CMD ["/sbin/tini", "--", "/opt/entrypoint.sh"]
