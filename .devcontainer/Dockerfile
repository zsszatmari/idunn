# syntax=docker/dockerfile:1

# Everything from here down to the "===== Rust" banner is a language-agnostic dev
# base — Debian + apt tooling + a non-root user + Node + Claude Code. Another
# project reuses it by copying this file and deleting the Rust section (see
# docs/tasks/0003-devcontainer-base-image-restructure.md). The Rust toolchain is
# installed last, on top, so editing it does not bust the Node/npm layers, and so
# we own the rustup-init invocation (pinned + checksummed) rather than inheriting
# it from a `rust:*` base image.
FROM debian:trixie-slim

# Non-root user. uid/gid 1000 is the typical first human user on a Linux host;
# if it differs, the devcontainer CLI's `updateRemoteUserUID` adjusts it.
ARG USERNAME=dev

# BuildKit cache mounts keep the apt archives and package lists between image
# rebuilds, so editing this file no longer re-downloads every .deb. Debian's
# base image ships /etc/apt/apt.conf.d/docker-clean, which deletes downloaded
# archives after each install — remove it (and set Keep-Downloaded-Packages) or
# the cache mount stays empty. The mounts are build-only and absent from the
# final image, so it stays slim without the old `rm -rf /var/lib/apt/lists/*`.
# ca-certificates: rust:1-slim-trixie used to install this; plain
# debian:trixie-slim does not carry it, and the curl fetches below (nodejs.org,
# static.rust-lang.org) need a trust store.
# build-essential: node-gyp-compiled npm packages need a C toolchain, and the
# npm layers run before the Rust section — so it lives in this base layer, not
# the Rust one. cmake + perl are the only strictly-Rust apt deps (aws-lc-rs's
# AWS-LC C build); a non-Rust reuse can drop just those two.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache \
 && groupadd --gid 1000 $USERNAME \
 && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash $USERNAME \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      sudo \
      git \
      curl \
      build-essential \
      cmake \
      perl \
      just \
 && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
 && chmod 0440 /etc/sudoers.d/$USERNAME

# Node.js 22, pinned, from nodejs.org's official build. Debian trixie's apt only
# ships Node 20, but Claude Code and the ACP bridge below both require node >=22.
# Fetched during the image build (not proxied) and unpacked into /usr/local so
# `node` and the bundled `npm` land on PATH. Chosen over NodeSource's apt repo:
# one fetch from a fast CDN, no third-party apt source, and no full `apt-get
# update` (which pulled ~37 MB of transitive deps and took ~15 min on arm64).
# The .tar.gz, not .tar.xz, so the slim base's `tar` needs no xz-utils.
ARG NODE_VERSION=22.23.2
RUN arch="$(dpkg --print-architecture)" \
 && case "$arch" in \
      amd64) node_arch=x64 ;; \
      arm64) node_arch=arm64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" \
      | tar -xz -C /usr/local --strip-components=1 --no-same-owner \
 && node --version \
 && npm --version

# JSON language server for Zed, baked into the image so the container never has to
# reach registry.npmjs.org at runtime (the egress proxy blocks it, and an image
# layer costs nothing where an allowlist entry is permanent). Zed picks up a
# `vscode-json-language-server` already on PATH the same way it picks up
# rust-analyzer. See docs/tasks/0001-devcontainer-agent-egress.md.
RUN npm install -g vscode-langservers-extracted \
 && npm cache clean --force

# Claude Code and its Zed ACP bridge (@agentclientprotocol/claude-agent-acp — the
# non-deprecated successor to @zed-industries/claude-code-acp), baked in for the same
# reason as the JSON LSP above: the runtime egress proxy blocks registry.npmjs.org,
# and an image layer is free where an allowlist entry is permanent. The trailing
# `claude --version` is deliberate — it forces any first-run native-binary download
# to happen here, at build time, where there is no proxy, and fails the build loudly
# if it cannot. See docs/agent-egress-gateway.md.
RUN npm install -g @anthropic-ai/claude-code @agentclientprotocol/claude-agent-acp \
 && npm cache clean --force \
 && claude --version

# Claude Code's per-user state dir, created and owned by $USERNAME in the image so the
# `claude-home` named volume mounted here (see .devcontainer/compose.yaml) inherits that
# ownership on first use. Without this Docker creates the mountpoint root-owned and the
# agent's transcript/settings writes fail with EACCES.
RUN mkdir -p /home/$USERNAME/.claude \
 && chown $USERNAME:$USERNAME /home/$USERNAME/.claude

# ======================= Rust (self-installed, last) =======================
# A non-Rust project deletes everything from this banner down. RUSTUP_HOME /
# CARGO_HOME / PATH were an ENV layer supplied by rust:1-slim-trixie; declared
# here so the reusable base above carries no Rust env.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# rust:1-slim-trixie is debian:trixie-slim plus one RUN: install
# ca-certificates/gcc/libc6-dev, fetch a pinned + SHA-256-checked rustup-init,
# run it, then `chmod -R a+w $RUSTUP_HOME $CARGO_HOME`. We reproduce that step —
# ca-certificates and a C toolchain are already in the apt layer above.
#
# rustup-init is pinned to 1.29.0 with per-arch SHA-256 (values from
# github.com/rust-lang/docker-rust). Build-time fetch from static.rust-lang.org,
# unproxied (image builds run outside the compose network). amd64 + arm64 only,
# matching the Node block.
#
# The stable toolchain tracks the `stable` channel (not a pinned version) —
# newest stable at every image rebuild, closest to the floating rust:1-slim-trixie
# behaviour it replaces. Nothing names `+stable` explicitly, so there is no
# duplicate-toolchain risk (see docs/tasks/0002-devcontainer-image-slim-down.md).
# Nightly stays floating — it is only ever the coverage toolchain (llvm-tools;
# #[cfg(coverage)] is unsupported on stable), so --profile minimal keeps it to
# just that.
#
# rustup-init + components + nightly are one RUN so the single trailing
# `chmod -R a+w` is correct with zero copy-up: every file under $RUSTUP_HOME /
# $CARGO_HOME is born in this layer (this is exactly what the official `rust`
# image does). The pathology fixed in task 0002 was a recursive chmod in a
# *later* layer than the toolchain tree, which forced overlayfs to copy the
# whole tree up. Cost of one RUN: adding a component later rebuilds the whole
# toolchain layer — accepted, these change rarely.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64)  rustArch='x86_64-unknown-linux-gnu';  sha='4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10' ;; \
      arm64)  rustArch='aarch64-unknown-linux-gnu'; sha='9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792' ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLO "https://static.rust-lang.org/rustup/archive/1.29.0/${rustArch}/rustup-init"; \
    echo "${sha} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain stable --default-host "${rustArch}"; \
    rm rustup-init; \
    rustup component add rust-analyzer rust-src clippy rustfmt; \
    rustup toolchain install nightly --profile minimal --component llvm-tools; \
    chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

# `cargo install` builds these tools from source — several minutes from scratch,
# and any change to a layer above forces the whole thing again. Cache both the
# crate downloads and the intermediate build artifacts (an explicit --target-dir
# on a cache mount) so a rebuild only redoes what actually changed. All three
# mounts are build-only and absent from the final image; the installed binaries
# land in $CARGO_HOME/bin, which is not mounted, so they persist.
# Separate RUN from the toolchain above: it carries the BuildKit cache mounts and
# changes independently of the toolchain.
# CARGO_PROFILE_RELEASE_STRIP=symbols only trims the symbol table here (~1 MB) —
# cargo strips debuginfo from release builds by default — but these are dev
# tools never debugged from this image, so it is kept for explicitness.
# `umask 0000` + two scoped `find … ! -perm -o+w -exec chmod a+w` tails, NOT
# `chmod -R a+w $CARGO_HOME`: a recursive chmod in this later layer would change
# the mode of the toolchain tree from the RUN above and copy it all up (the
# task 0002 pathology). The `find`s only match files this RUN created:
#   1. the installed binaries in $CARGO_HOME/bin;
#   2. root-created files at the $CARGO_HOME root — notably `.global-cache`,
#      cargo's GC bookkeeping, which `dev`'s later `cargo build` must write.
#      `-maxdepth 1 -type f` keeps it out of the registry/git cache mounts,
#      whose contents never enter the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/opt/toolbuild \
    umask 0000 && CARGO_PROFILE_RELEASE_STRIP=symbols cargo install --locked --target-dir /opt/toolbuild \
      cargo-llvm-cov \
      cargo-hack \
      cargo-minimal-versions \
      cargo-deny \
 && find /usr/local/cargo/bin ! -perm -o+w -exec chmod a+w {} + \
 && find /usr/local/cargo -maxdepth 1 -type f ! -perm -o+w -exec chmod a+w {} +

USER $USERNAME

