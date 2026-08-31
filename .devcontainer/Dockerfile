FROM rust:1-trixie

RUN rustup component add rust-analyzer rust-src clippy rustfmt

# Non-root user. uid/gid 1000 is the typical first human user on a Linux host;
# if it differs, the devcontainer CLI's `updateRemoteUserUID` adjusts it.
ARG USERNAME=dev
RUN groupadd --gid 1000 $USERNAME \
 && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash $USERNAME \
 && apt-get update \
 && apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/* \
 && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
 && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
