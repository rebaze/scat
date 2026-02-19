#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR=$(mktemp -d)

docker run --rm -it -v "$OUTPUT_DIR:/output" ubuntu:24.04 bash -c '
set -euo pipefail

apt-get update && apt-get install -y curl git

# Install Homebrew
NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

# Install scat from tap
brew install rebaze/tap/scat

# Verify
scat version

# Clone a small Go project and scan it
git clone --depth 1 https://github.com/spf13/cobra /tmp/cobra
scat analyze --output-dir /output /tmp/cobra
'

echo "Reports written to: $OUTPUT_DIR"
open "$OUTPUT_DIR"/cobra-summary.html
