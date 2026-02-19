#!/usr/bin/env bash
set -euo pipefail

docker run --rm -it ubuntu:24.04 bash -c '
set -euo pipefail

apt-get update && apt-get install -y curl git

# Install Homebrew
NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

# Install scat from tap
brew install rebaze/tap/scat

# Verify
scat version
'
