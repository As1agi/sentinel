#!/bin/bash

set -eou pipefail

# Dynamically resolve runtime user and absolute project directory
RUN_USER="$(whoami)"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Ensure logs directory exists
mkdir -p "${PROJECT_DIR}/logs"

# Ensure runner script is executable
chmod +x "${PROJECT_DIR}/sentinel.sh"

CRON_LOG="${PROJECT_DIR}/logs/cron_execution.log"
CRON_TAG="# SENTINEL_CRON_JOB"


# Quoted paths protect against directory names containing spaces
CRON_JOB="* */18 * * * cd \"${PROJECT_DIR}\" && ./sentinel.sh >> \"${CRON_LOG}\" 2>&1 ${CRON_TAG}"

echo "[+] Detecting environment..."
echo "    User: ${RUN_USER}"
echo "    Path: ${PROJECT_DIR}"

# Check if the job is already installed in user's crontab
if crontab -l 2>/dev/null | grep -Fq "${CRON_TAG}"; then
    echo "[=] Cron job already installed for user '${RUN_USER}'."
    echo "[+] Updating crontab entry..."

    # Remove existing Sentinel entry and re-add updated path/schedule
    (crontab -l 2>/dev/null | grep -v "${CRON_TAG}" || true; echo "${CRON_JOB}") | crontab -
    echo "[+] Updated crontab successfully."
else
    echo "[+] Installing new cron entry for '${RUN_USER}'..."

    # Safely append to existing crontab without overwriting other jobs
    (crontab -l 2>/dev/null || true; echo "${CRON_JOB}") | crontab -
    echo "[+] Installed successfully! Sentinel is set to run every 1 minute."
fi

echo ""
echo "[+] Active crontab entry for ${RUN_USER}:"
crontab -l | grep "${CRON_TAG}"
