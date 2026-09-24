#!/bin/bash

set -eou pipefail

RUN_USER="$(whoami)"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
 
mkdir -p "${PROJECT_DIR}/logs"
 
chmod +x "${PROJECT_DIR}/sentinel.sh"

CRON_LOG="${PROJECT_DIR}/logs/cron_execution.log"
CRON_TAG="# SENTINEL_CRON_JOB"

CRON_JOB="0 */18 * * * flock -n \"${PROJECT_DIR}/sentinel.lock\" -c \"cd \\\"${PROJECT_DIR}\\\" && ./sentinel.sh\" >> \"${CRON_LOG}\" 2>&1 ${CRON_TAG}"

echo "[+] Detecting environment..."
echo "    User: ${RUN_USER}"
echo "    Path: ${PROJECT_DIR}"
 
if crontab -l 2>/dev/null | grep -Fq "${CRON_TAG}"; then
    echo "[=] Cron job already installed for user '${RUN_USER}'."
    echo "[+] Updating crontab entry..."

    (crontab -l 2>/dev/null | grep -v "${CRON_TAG}" || true; echo "${CRON_JOB}") | crontab -
    echo "[+] Updated crontab successfully."
else
    echo "[+] Installing new cron entry for '${RUN_USER}'..."

    (crontab -l 2>/dev/null || true; echo "${CRON_JOB}") | crontab -
    echo "[+] Installed successfully! Sentinel is set to run every 1 minute."
fi

echo ""
echo "[+] Active crontab entry for ${RUN_USER}:"
crontab -l | grep "${CRON_TAG}"
