FROM rust:1-slim-trixie

# Non-root user. uid/gid 1000 is the typical first human user on a Linux host;
# if it differs, the devcontainer CLI's `updateRemoteUserUID` adjusts it.
ARG USERNAME=dev
# build-essential (for a C++ compiler)/cmake/perl: the slim base only ships
# gcc, but the default aws_lc_rs feature compiles AWS-LC's C/C++ source.
RUN groupadd --gid 1000 $USERNAME \
  && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash $USERNAME \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
  sudo \
  git \
  build-essential \
  cmake \
  perl \
  just \
  && rm -rf /var/lib/apt/lists/* \
  && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME

RUN rustup component add rust-analyzer rust-src clippy rustfmt
# nightly needed for coverage,#cfg[coverage(off)] is unsupported on stable
RUN rustup toolchain install nightly --component llvm-tools

