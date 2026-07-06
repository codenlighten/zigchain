# ZigChain node — reproducible, statically-linked container image.
#
#   docker build -t zigchain .
#   docker run -d --restart unless-stopped -p 9000:9000 -v zc:/data \
#       -e ZIGCHAIN_MINE=true zigchain
#
# Config is via environment variables (see deploy/docker-entrypoint.sh).

# ---- build stage: pinned Zig, static musl binary ----
FROM debian:bookworm-slim AS build

# The exact nightly this codebase is written against, pinned to a durable mirror
# (upstream ziglang.org rotates nightlies out).
ARG ZIG_VERSION=0.16.0-dev.3153+d6f43caad
ARG ZIG_URL=https://pkg.machengine.org/zig/zig-x86_64-linux-${ZIG_VERSION}.tar.xz

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl xz-utils ca-certificates binutils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "${ZIG_URL}" -o /tmp/zig.tar.xz \
 && mkdir -p /opt/zig \
 && tar -xf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
 && rm /tmp/zig.tar.xz
ENV PATH="/opt/zig:${PATH}"

WORKDIR /src
COPY . .

# Static musl build → runs on a bare Alpine (or scratch) image. `-Dnode-safe`
# builds the node in ReleaseSafe (integer-overflow / bounds traps on); with the
# musl (libc) target this uses the C allocator, so there is no leak-tracking
# noise while keeping the safety checks a consensus node wants.
RUN zig build -Dtarget=x86_64-linux-musl -Dnode-safe=true \
 && strip zig-out/bin/zigchain-node

# ---- runtime stage: minimal ----
FROM alpine:3.20
RUN adduser -D -H -u 10001 zigchain && mkdir -p /data && chown zigchain /data
COPY --from=build /src/zig-out/bin/zigchain-node /usr/local/bin/zigchain-node
COPY deploy/docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER zigchain
VOLUME /data
ENV ZIGCHAIN_PORT=9000 \
    ZIGCHAIN_DATADIR=/data \
    ZIGCHAIN_NAME=zigchain
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
