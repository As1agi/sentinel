#!/bin/bash
set -eou pipefail

#Ubuntu: https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip
#Debian: https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip
#Rocky Linux: https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip
#AlmaLinux: https://storage.googleapis.com/osv-vulnerabilities/AlmaLinux/all.zip

# Gets the absolute path of the directory containing THIS script file
BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

UBUNTU_DIR="${BASE_DIR}/ubuntu"
DEBIAN_DIR="${BASE_DIR}/debian"

# ensure the directories exist
mkdir -p "${UBUNTU_DIR}" "$DEBIAN_DIR"

#Get the Ubuntu data and save it in ubuntu.zip
echo "[*] Downloading Ubuntu data"
wget -q -O "${UBUNTU_DIR}/ubuntu.zip" --show-progress   https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip

#Get the Debian data and save it
echo "[*] Downloading Debian data"
wget -q -O "${DEBIAN_DIR}/debian.zip" --show-progress  https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip

echo "[*] Extracting Debian advisories..."
unzip -q -o "${DEBIAN_DIR}/debian.zip" -d "${DEBIAN_DIR}" && rm "${DEBIAN_DIR}/debian.zip"

echo "[*] Extracting Ubuntu advisories..."
unzip -q -o "${UBUNTU_DIR}/ubuntu.zip" -d "${UBUNTU_DIR}" && rm "${UBUNTU_DIR}/ubuntu.zip"
