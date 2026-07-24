#!/usr/bin/env bash
# run_demos.sh -- build and run all three local-CLI-threat-model demonstrations, capturing real output.
# Uses only clearly-fake decoy files; never prints file contents. Cleans up decoys at the end.
set -uo pipefail
cd "$(dirname "$0")"
HOME_DIR="${HOME:?}"
PROJ="/tmp/project"
DOTFILE="$HOME_DIR/.demo_probe_dotfile"        # decoy "secret dotfile" OUTSIDE the pin
SSHKEY="$HOME_DIR/.ssh/demo_probe_key"          # decoy "ssh key" OUTSIDE the pin (NOT a real key)
cleanup(){ rm -f "$DOTFILE" "$SSHKEY"; }
trap cleanup EXIT

line(){ printf '\n===== %s =====\n' "$1"; }

line "HOST / PROVENANCE"
uname -sr
gcc --version | head -1
printf 'landlock ABI: '; ./_abi 2>/dev/null || {
  cat > /tmp/_abi.c <<'EOF'
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
int main(){ long v=syscall(444,0,0,1); printf("%ld\n", v); return 0; }
EOF
  gcc -O2 /tmp/_abi.c -o ./_abi && ./_abi; }

line "BUILD"
gcc -O2 -static rw_probe.c -o rw_probe && echo "rw_probe: $(file -b rw_probe | cut -d, -f1-2)"
gcc -O2 landlock_rwpin.c -o landlock_rwpin && echo "landlock_rwpin: built"
gcc -O2 ioctl_decode.c   -o ioctl_decode   && echo "ioctl_decode: built"

# ---------------------------------------------------------------------------
line "DEMO 1 -- ENVIRONMENT INHERITANCE (inherited-context risk)"
bash ./env_inherit.sh

# ---------------------------------------------------------------------------
line "DEMO 2 -- LANDLOCK READ+WRITE HARD-PIN"
mkdir -p "$PROJ"
echo "inside-project data" > "$PROJ/inside.txt"
echo "FAKE-decoy-dotfile-not-a-secret"   > "$DOTFILE"
echo "FAKE-decoy-key-NOT-a-real-ssh-key" > "$SSHKEY"
cp rw_probe "$PROJ/rw_probe"

echo "-- (a) BASELINE, no pin: the same probe reaches inside AND outside --"
"$PROJ/rw_probe" "$PROJ/inside.txt" "$DOTFILE" "$SSHKEY"

echo
echo "-- (b) PINNED to $PROJ via landlock_rwpin: outside read+write denied --"
./landlock_rwpin "$PROJ" "$PROJ/rw_probe" "$PROJ/inside.txt" "$DOTFILE" "$SSHKEY"

# ---------------------------------------------------------------------------
line "DEMO 3 -- WHY SECCOMP CANNOT FILTER ioctl(2)"
./ioctl_decode

line "DONE (decoys removed on exit)"
