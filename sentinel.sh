#!/bin/bash

set -eou pipefail

# Export explicit path
export PATH="/usr/local/go/bin:${HOME}/go/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

#Date for logging
DATE="$(date +'%Y-%m-%d_%H-%M-%S')"
# Base directory
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Server
SERVER_DIR="${BASE_DIR}/server"
SERVER_SCRIPT_DIR="${SERVER_DIR}/scripts"
SERVER_BIN="${SERVER_DIR}/server"

# SBOM
SBOM_DIR="${BASE_DIR}/sbom"
SBOM_BIN="${SBOM_DIR}/sbom"

# Log directories
LOG_DIR="${BASE_DIR}/logs"
mkdir -p "${LOG_DIR}"
SERVER_LOG="${LOG_DIR}/server_${DATE}.log"
SBOM_LOG="${LOG_DIR}/sbom_${DATE}.log"

# Ensure bins are built
make -C "${SBOM_DIR}" build
make -C "${SERVER_DIR}" build

# Ensure executables
chmod +x "${SERVER_SCRIPT_DIR}"/* 2>/dev/null || true
chmod +x "${SERVER_BIN}" "${SBOM_BIN}"

# Fetch CVEs & fill up the DB
echo "[+] Executing CVE fetch pipeline..."
bash "${SERVER_SCRIPT_DIR}/FetchOsvData.sh"
bash "${SERVER_SCRIPT_DIR}/FetchNvdData.sh"
echo "[+] Fetch pipeline completed..."

echo "[+] Populating database..."
"${SERVER_BIN}" database --populate

# Check if Server is running; start once if down
if nc -z 127.0.0.1 8080 2>/dev/null; then
    echo "[+] Server is already running on port 8080."
else
    echo "[+] Server not running. Starting server process..."
    cd "${SERVER_DIR}"
    "${SERVER_BIN}" server > "${SERVER_LOG}" 2>&1 &

    echo "[+] Waiting for port 8080 listener to bind..."
    MAX_RETRIES=15
    COUNTER=0

    while ! nc -z 127.0.0.1 8080 2>/dev/null && [ ${COUNTER} -lt ${MAX_RETRIES} ]; do
        sleep 3
        COUNTER=$((COUNTER + 1))
    done

    # Verify final binding status
    if ! nc -z 127.0.0.1 8080 2>/dev/null; then
        echo "[-] ERROR: Sentinel service failed to bind to port 8080 within timeout." >&2
        exit 1
    fi
    echo "[+] Server successfully bound to port 8080."
fi

# Dispatch SBOM Engine
echo "[+] Executing SBOM scan runner..."
"${SBOM_BIN}" > "${SBOM_LOG}" 2>&1

echo "[+] Execution pipeline completed successfully"
