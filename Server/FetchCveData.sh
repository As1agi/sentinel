#!/bin/bash
set -eou pipefail

BASE_DIR="${HOME}/.local/share/sentinel"
OSV_DIR="${BASE_DIR}/data/cve/osv/raw"


DISTROS=("Ubuntu" "Debian")

for distro in "${DISTROS[@]}"; do
    # Convert to lowercase for local folder structure (Ubuntu -> ubuntu)
    distro_lower=$(echo "${distro}" | tr '[:upper:]' '[:lower:]')
    target_dir="${OSV_DIR}/${distro_lower}"
    zip_file="${target_dir}/${distro_lower}.zip"
    url="https://storage.googleapis.com/osv-vulnerabilities/${distro}/all.zip"

    mkdir -p "${target_dir}"

    echo "[*] Downloading ${distro} data..."
    wget -q -O "${zip_file}" --show-progress "${url}"

    echo "[*] Extracting ${distro} advisories..."
    unzip -q -o "${zip_file}" -d "${target_dir}"
    rm -f "${zip_file}"
done

echo "[+] Done. Data extracted to ${OSV_DIR}"