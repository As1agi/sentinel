#!/bin/bash

set -eou pipefail


BASE_DIR="${HOME}/.local/share/sentinel"
DATA_DIR="${BASE_DIR}/data/cve/nvd/raw"

# Ensure jq is available for JSON validation
command -v jq >/dev/null 2>&1 || { echo "[-] Error: 'jq' is required but not installed." >&2; exit 1; }

declare -A FEEDS=(
    ["ubuntu"]="https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:canonical:ubuntu_linux"
    ["debian"]="https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:debian:debian_linux"
)

for distro in "${!FEEDS[@]}"; do
    target_dir="${DATA_DIR}/${distro}"
    json_file="${target_dir}/${distro}.json"
    tmp_json="${json_file}.tmp"
    url="${FEEDS[${distro}]}"

    if [[ ! -f $"target_dir" ]]; then mkdir -p "${target_dir}" 
    fi

    echo "[*] Processing ${distro} NVD JSON feed..."

    # Validate existing local JSON
    if [[ -f "${json_file}" ]]; then
        if ! jq empty "${json_file}" 2>/dev/null; then
            echo "    [!] Existing local JSON is corrupt. Purging before sync..."
            rm -f "${json_file}"
        fi
    fi

    rm -f "${tmp_json}"

    if [[ -f "${json_file}" ]]; then
        curl -s -L -z "${json_file}" -o "${tmp_json}" "${url}"
    else
        curl -L --progress-bar -o "${tmp_json}" "${url}"
    fi

    if [[ ! -f "${tmp_json}" || ! -s "${tmp_json}" ]]; then
        echo "    [=] Remote feed unchanged (HTTP 304). Local cache is up to date."
        rm -f "${tmp_json}"
        continue
    fi

    # Verify JSON structure before overwriting
    echo "    [*] New update received. Verifying JSON integrity..."
    if jq empty "${tmp_json}" 2>/dev/null; then
        mv -f "${tmp_json}" "${json_file}"
        echo "    [+] Integrity verified. Updated ${json_file}"
    else
        echo "    [-] ERROR: Downloaded JSON payload for ${distro} is invalid or rate-limited" >&2
        rm -f "${tmp_json}"
        exit 1
    fi
done
