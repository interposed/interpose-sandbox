# interpose-sandbox AGENT IMAGE — rootfs contents.
#
# A Firecracker/microVM rootfs with the interpose enforcer (public license key
# baked in via ldflags), the vsock guest-agent, node + pi, busybox init, and the
# boot wiring. build.sh exports this to an ext4 and (optionally) publishes it as
# an OCI image that `interpose-sandbox new` pulls (like interpose-kernel).
#
# Binaries in bin/ are cross-built by build.sh (interpose from the interpose
# repo with the pubkey baked; interpose-guest from this repo).
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      busybox-static ca-certificates git iproute2 procps kmod \
    && rm -rf /var/lib/apt/lists/*

# The pi harness fronts claude/codex/… via subscription; individual agent CLIs
# come through pi, so the image needs only node + pi.
RUN npm install -g @earendil-works/pi-coding-agent && npm cache clean --force

COPY bin/interpose        /usr/local/bin/interpose
COPY bin/interpose-guest  /usr/sbin/interpose-guest
COPY rootfs-overlay/      /

RUN ln -sf /bin/busybox /usr/sbin/init \
 && chmod +x /usr/sbin/interpose-boot /usr/sbin/interpose-workspace /usr/sbin/interpose-guest \
             /usr/sbin/interpose-selftest /usr/local/bin/interpose \
 && mkdir -p /var/lib/interpose /workspace /root /var/log
