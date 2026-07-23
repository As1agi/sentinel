#!/bin/bash
set -eou pipefail

BASE_DIR="${HOME}/.local/share/sentinel"
OSV_DIR="${BASE_DIR}/data/cve/osv/raw"
DISTROS=("Ubuntu" "Debian")

for distro in "${DISTROS[@]}"; do
    distro_lower=$(echo "${distro}" | tr '[:upper:]' '[:lower:]')
    target_dir="${OSV_DIR}/${distro_lower}"
    zip_file="${target_dir}/${distro_lower}.zip"
    tmp_zip="${target_dir}/${distro_lower}.zip.tmp"
    url="https://storage.googleapis.com/osv-vulnerabilities/${distro}/all.zip"

    mkdir -p "${target_dir}"

    echo "[*] Processing ${distro} OSV feed..."

    # Pre-check existing local ZIP integrity
    if [[ -f "${zip_file}" ]]; then
        if ! unzip -t -q "${zip_file}" 2>/dev/null; then
            echo "    [!] Existing local archive is corrupt. Purging before sync..."
            rm -f "${zip_file}"
        fi
    fi

    #  Conditional Fetch using curl -z
    # -z "${zip_file}": Only fetch if remote file is NEWER than local zip_file
    # -o "${tmp_zip}": Stream incoming download to temporary file
    rm -f "${tmp_zip}"

    echo "    [*] Checking remote repository for updates..."

    if [[ -f "${zip_file}" ]]; then
        # Local file exists: send If-Modified-Since header
        curl -s -L -z "${zip_file}" -o "${tmp_zip}" "${url}"
    else
        # No local file exists: download full file with progress bar
        curl -L --progress-bar -o "${tmp_zip}" "${url}"
    fi

    #  Evaluate curl outcome
    if [[ ! -f "${tmp_zip}" || ! -s "${tmp_zip}" ]]; then
        # 0 bytes downloaded or tmp file doesn't exist -> HTTP 304 Not Modified
        echo "    [=] Remote feed unchanged (HTTP 304). Local archive is up to date"

        rm -f "${tmp_zip}"
        continue
    else
        # File downloaded -> Verify integrity before replacing local archive
        echo "    [*] New update received. Verifying archive integrity..."
        if unzip -t -q "${tmp_zip}" 2>/dev/null; then
            mv -f "${tmp_zip}" "${zip_file}"
            echo "    [+] Integrity verified. Updated ${zip_file}"
        else
            echo "    [-] ERROR: Downloaded payload for ${distro} is corrupt" >&2
            rm -f "${tmp_zip}"
            exit 1
        fi
    fi

    # Extract advisories to target directory
    echo "    [*] Extracting ${distro} advisories..."
    unzip -q -o "${zip_file}" -d "${target_dir}"
    echo "    [+] ${distro} sync complete"
done

echo "[+] All OSV data fully synced and extracted to ${OSV_DIR}"
