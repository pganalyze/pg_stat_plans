# syntax=docker/dockerfile:1

# Build an OCI image containing the pg_stat_plans extension, laid out for use as
# a CloudNativePG extension image volume:
#   https://cloudnative-pg.io/docs/current/imagevolume_extensions/

ARG PG_MAJOR=18
ARG DEBIAN_SUITE=trixie

FROM debian:${DEBIAN_SUITE}-slim AS builder
ARG PG_MAJOR

# Add the PGDG apt repository, build toolchain, and the matching PostgreSQL
# server development headers.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        build-essential pkg-config \
        libzstd-dev libssl-dev libkrb5-dev; \
    install -d /usr/share/postgresql-common/pgdg; \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc; \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(. /etc/os-release && echo "$VERSION_CODENAME")-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-server-dev-${PG_MAJOR}; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build from source, stage-install into /dest, then collect just the extension
# artifacts into the /lib + /share layout CloudNativePG expects at the root.
RUN set -eux; \
    PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config; \
    make -j"$(nproc)" PG_CONFIG="$PG_CONFIG" all; \
    make PG_CONFIG="$PG_CONFIG" DESTDIR=/dest install; \
    mkdir -p /out/lib /out/share/extension; \
    cp /dest/usr/lib/postgresql/${PG_MAJOR}/lib/pg_stat_plans.so /out/lib/; \
    cp /dest/usr/share/postgresql/${PG_MAJOR}/extension/pg_stat_plans.control /out/share/extension/; \
    cp /dest/usr/share/postgresql/${PG_MAJOR}/extension/pg_stat_plans--*.sql /out/share/extension/

FROM scratch
COPY --from=builder /out/ /
