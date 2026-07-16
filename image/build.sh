#!/usr/bin/env bash
# Build the interpose-sandbox AGENT IMAGE: a Firecracker/microVM rootfs with the
# interpose enforcer (public license key baked in), the vsock guest-agent, and
# node + pi. Produces an ext4, and — with PUBLISH/PACKAGE — an OCI image
# (FROM scratch, /agent-rootfs.ext4) that `interpose-sandbox new` pulls, exactly
# like interpose-kernel.
#
# Only host requirement is docker (mkfs runs in a builder container). Cross-repo:
# builds `interpose` from INTERPOSE_SRC (default ../../interpose) with the pubkey.
#
#   ARCH=arm64 ./build.sh                       # ext4 only
#   PACKAGE=1 AGENT_TAG=org/interpose-agent:… ./build.sh   # + local OCI image
#   PUBLISH=1 AGENT_TAG=org/interpose-agent:… ./build.sh   # + docker push
#   LIC=~/kernel-check/license-state.tgz ./build.sh         # bake a license (validation)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="${ARCH:-arm64}"
OUT="${OUT:-$DIR/agent-rootfs.ext4}"
SIZE="${SIZE:-2G}"
LIC="${LIC:-}"
PUBKEY="${INTERPOSE_PUBKEY:-4mi74COnx9BLRW+RCl6g7lAa3CG+E+OVnHP5KYmlywg=}"
INTERPOSE_SRC="${INTERPOSE_SRC:-$DIR/../../interpose}"
KERNEL_TAG="${KERNEL_TAG:-startaworldpeace/interpose-kernel:ubuntu-24.04-bpf-lsm-v0.1.0}"
AGENT_TAG="${AGENT_TAG:-startaworldpeace/interpose-agent:ubuntu-24.04-${ARCH}-v0.1.0}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "==> cross-build binaries (linux/$ARCH)"
mkdir -p "$DIR/bin"
( cd "$DIR/.." && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$DIR/bin/interpose-guest" ./cmd/interpose-guest )
if [ ! -x "$DIR/bin/interpose" ]; then
  [ -d "$INTERPOSE_SRC" ] || { echo "ERROR: need the interpose repo at INTERPOSE_SRC=$INTERPOSE_SRC (or a prebuilt image/bin/interpose)"; exit 1; }
  ( cd "$INTERPOSE_SRC" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
      -ldflags "-s -w -X github.com/interposed/interpose/pkg/license.pubkeyB64=$PUBKEY" \
      -o "$DIR/bin/interpose" ./cmd/interpose )
fi

echo "==> build rootfs container (node + pi + interpose + guest-agent)"
docker build --platform "linux/$ARCH" -t interpose-agent-rootfs:build "$DIR"

echo "==> export container filesystem"
cid="$(docker create --platform "linux/$ARCH" interpose-agent-rootfs:build /bin/true)"
docker export "$cid" > "$tmp/rootfs.tar"; docker rm "$cid" >/dev/null

echo "==> pull kernel modules from $KERNEL_TAG (best-effort)"
kcid="$(docker create --platform "linux/$ARCH" --entrypoint=/kernel "$KERNEL_TAG")" 2>/dev/null || kcid=""
[ -n "$kcid" ] && { docker cp "$kcid:/kernel.tar" "$tmp/kernel.tar" 2>/dev/null || true; docker rm "$kcid" >/dev/null; }

[ -n "$LIC" ] && cp "$LIC" "$tmp/license.tgz" && echo "==> baking license state from $LIC"

echo "==> assemble ext4"
outdir="$(dirname "$OUT")"; outname="$(basename "$OUT")"
docker run --rm --platform "linux/$ARCH" -v "$tmp:/w" -v "$outdir:/out" debian:bookworm-slim bash -c "
  set -e
  apt-get update -qq && apt-get install -y -qq e2fsprogs >/dev/null
  R=/rootfs; mkdir -p \$R
  tar -C \$R -xf /w/rootfs.tar
  printf '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n' > \$R/etc/hosts
  [ -f /w/kernel.tar ]  && tar -C \$R -xf /w/kernel.tar 2>/dev/null || true
  [ -f /w/license.tgz ] && tar -C \$R -xzf /w/license.tgz 2>/dev/null || true
  truncate -s $SIZE /out/$outname
  mkfs.ext4 -q -F -d \$R /out/$outname
  echo \"    ext4: \$(ls -lh /out/$outname | awk '{print \$5}')\"
"

if [ -n "${PACKAGE:-}${PUBLISH:-}" ]; then
  echo "==> package OCI image $AGENT_TAG"
  pkg="$tmp/oci"; mkdir -p "$pkg"; cp "$OUT" "$pkg/agent-rootfs.ext4"
  cat > "$pkg/rootfs-info" <<EOF
ARCH=$ARCH
BASE=node:22-bookworm-slim
KERNEL_TAG=$KERNEL_TAG
PUBKEY=$PUBKEY
EOF
  printf 'FROM scratch\nCOPY agent-rootfs.ext4 /agent-rootfs.ext4\nCOPY rootfs-info /rootfs-info\n' > "$pkg/Dockerfile"
  docker build --platform "linux/$ARCH" -t "$AGENT_TAG" "$pkg"
  [ -n "${PUBLISH:-}" ] && { echo "==> push $AGENT_TAG"; docker push "$AGENT_TAG"; }
fi
echo "==> done: $OUT"
