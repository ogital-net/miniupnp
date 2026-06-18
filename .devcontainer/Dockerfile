FROM mcr.microsoft.com/devcontainers/base:bookworm

# Add fd.io VPP packagecloud repository (https://packagecloud.io/fdio/release)
# fd.io only publishes amd64 packages; the container is pinned to linux/amd64.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://packagecloud.io/fdio/release/gpgkey \
       | gpg --dearmor -o /etc/apt/keyrings/fdio_release-archive-keyring.gpg \
    && chmod 0644 /etc/apt/keyrings/fdio_release-archive-keyring.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/fdio_release-archive-keyring.gpg] \
https://packagecloud.io/fdio/release/debian/ bookworm main" \
       > /etc/apt/sources.list.d/fdio_release.list

# VPP runtime + development packages
#   vpp              – VPP daemon; also installs libvapiclient.so (needed for -lvapiclient)
#   vpp-dev          – VAPI headers (vapi/*.h, vapiclient.h) and .api.json files
#   vpp-plugin-core  – NAT44-ED plugin required at runtime
#   libvppinfra      – VPP infrastructure runtime library
#   libvppinfra-dev  – VPP infrastructure development headers
#
# miniupnpd build dependencies
#   build-essential  – gcc, make, binutils
#   autoconf         – needed by miniupnpd's configure script
#   pkg-config       – pkg-config lookups in configure
#   uuid-dev         – libuuid (miniupnpd UUIDLIB)
# Two shims are needed during the VPP install inside an unprivileged build container:
#   policy-rc.d  – prevents dpkg from starting the vpp.service via invoke-rc.d
#   sysctl shim  – vpp's post-install script calls /usr/sbin/sysctl --system to
#                  apply hugepages/kernel params; those calls always fail with
#                  EPERM in a Docker build container.  dpkg-divert moves the real
#                  binary aside and replaces it with a no-op shim for the duration
#                  of the install, then restores the original afterwards.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && dpkg-divert --local --rename --add /usr/sbin/sysctl \
    && printf '#!/bin/sh\nexit 0\n' > /usr/sbin/sysctl \
    && chmod +x /usr/sbin/sysctl \
    && apt-get update && apt-get install -y --no-install-recommends \
        vpp \
        vpp-dev \
        vpp-plugin-core \
        libvppinfra \
        libvppinfra-dev \
        build-essential \
        autoconf \
        pkg-config \
        uuid-dev \
        libnftnl-dev \
        libmnl-dev \
        nftables \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d /usr/sbin/sysctl \
    && dpkg-divert --rename --remove /usr/sbin/sysctl
