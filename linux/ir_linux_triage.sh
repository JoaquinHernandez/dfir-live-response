#!/usr/bin/env bash
# ==============================================================================
# Enterprise DFIR Automated Live-Response Collector (Linux)
# Adheres to RFC 3227 Order of Volatility (Includes Memory Acquisition)
# ==============================================================================

set -o pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root to access volatile artifacts." >&2
   exit 1
fi

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
HOSTNAME=$(hostname -s 2>/dev/null || echo "unknown_host")
CASE_DIR="DFIR_TRIAGE_${HOSTNAME}_${TIMESTAMP}"
LOG_FILE="${CASE_DIR}/collector_execution.log"

mkdir -p "${CASE_DIR}"/{00_physical_memory,01_volatile_network,02_processes_memory,03_users_access,04_persistence,05_filesystem,06_logs_configs}

log_msg() {
    local MSG="[$(date -u +"%Y-%m-%d %H:%M:%SZ")] $1"
    echo -e "${MSG}" | tee -a "${LOG_FILE}"
}

run_triage() {
    local DESC="$1"
    local OUT_FILE="$2"
    shift 2
    log_msg "Executing: ${DESC}"
    {
        echo "=== [COMMAND]: $* ==="
        echo "=== [TIMESTAMP]: $(date -u +"%Y-%m-%d %H:%M:%SZ") ==="
        "$@"
        echo -e "\n=== [EXIT STATUS]: $? ==="
    } > "${OUT_FILE}" 2>&1
}

log_msg "[*] Starting live response evidence collection for: ${HOSTNAME}"

# ------------------------------------------------------------------------------
# 0. PHYSICAL MEMORY ACQUISITION (RFC 3227 - Highest Volatility)
# ------------------------------------------------------------------------------
log_msg "[+] Phase 0: Checking for LiME kernel module for memory acquisition..."
RAM_OUTPUT="${CASE_DIR}/00_physical_memory/physical_memory_${HOSTNAME}_${TIMESTAMP}.lime"

# Search for pre-compiled LiME module matching current kernel
LIME_MODULE=$(find . /opt /root /tmp -name "lime-$(uname -r).ko" -o -name "lime.ko" 2>/dev/null | head -n 1)

if [[ -n "${LIME_MODULE}" ]] && [[ -f "${LIME_MODULE}" ]]; then
    log_msg "[*] Found LiME module at ${LIME_MODULE}. Acquiring RAM..."
    insmod "${LIME_MODULE}" "path=${RAM_OUTPUT} format=lime"
    rmmod lime 2>/dev/null || true
    if [[ -f "${RAM_OUTPUT}" ]]; then
        log_msg "[+] Physical memory captured successfully: $(ls -lh "${RAM_OUTPUT}" | awk '{print $5}')"
    else
        log_msg "[-] LiME acquisition finished but memory file not found."
    fi
else
    log_msg "[!] LiME kernel module not found matching kernel $(uname -r). Skipping live RAM acquisition."
fi

# ------------------------------------------------------------------------------
# 1. VOLATILE NETWORK STATE
# ------------------------------------------------------------------------------
log_msg "[+] Phase 1: Capturing volatile network telemetry..."
run_triage "Socket statistics" "${CASE_DIR}/01_volatile_network/ss_all.txt" ss -tulanp -e -i
run_triage "Legacy Netstat" "${CASE_DIR}/01_volatile_network/netstat_tulpan.txt" netstat -tulpan -e
run_triage "Routing table" "${CASE_DIR}/01_volatile_network/ip_route.txt" ip route show table all
run_triage "ARP cache" "${CASE_DIR}/01_volatile_network/ip_neighbor_arp.txt" ip -s -s neigh show
run_triage "Network interfaces" "${CASE_DIR}/01_volatile_network/ip_addr_link.txt" ip -d address show
run_triage "Iptables rules" "${CASE_DIR}/01_volatile_network/iptables_rules.txt" iptables -L -n -v --line-numbers
run_triage "NFTables ruleset" "${CASE_DIR}/01_volatile_network/nftables_rules.txt" nft list ruleset

# ------------------------------------------------------------------------------
# 2. PROCESSES & MEMORY FOOTPRINT
# ------------------------------------------------------------------------------
log_msg "[+] Phase 2: Triaging process tree and execution state..."
run_triage "Process Forest" "${CASE_DIR}/02_processes_memory/ps_forest.txt" ps auxfww
run_triage "Extended process attributes" "${CASE_DIR}/02_processes_memory/ps_extended.txt" ps -eo user,pid,ppid,lstart,etime,cputime,nlwp,vsz,rss,stat,tty,security,cmd
run_triage "Open descriptors" "${CASE_DIR}/02_processes_memory/lsof_network_files.txt" lsof -n -P -R
run_triage "Loaded kernel modules" "${CASE_DIR}/02_processes_memory/lsmod.txt" lsmod
run_triage "Kernel sysctl configuration" "${CASE_DIR}/02_processes_memory/sysctl_all.txt" sysctl -a

# ------------------------------------------------------------------------------
# 3. USER SESSIONS & IDENTITY ARTIFACTS
# ------------------------------------------------------------------------------
log_msg "[+] Phase 3: Collecting logged-in users, identity, and auth state..."
run_triage "Current sessions" "${CASE_DIR}/03_users_access/who_w.txt" w
run_triage "Historical logons" "${CASE_DIR}/03_users_access/last_logons.txt" last -Faiwx
run_triage "Failed login attempts" "${CASE_DIR}/03_users_access/lastb_failures.txt" lastb -Faiwx
run_triage "Local accounts" "${CASE_DIR}/03_users_access/passwd.txt" cat /etc/passwd
run_triage "Local groups" "${CASE_DIR}/03_users_access/group.txt" cat /etc/group
run_triage "Sudoers rules" "${CASE_DIR}/03_users_access/sudoers.txt" cat /etc/sudoers /etc/sudoers.d/*

log_msg "Collecting shell history files without timestamp alteration..."
mkdir -p "${CASE_DIR}/03_users_access/histories"
find /root /home -maxdepth 2 -type f \( -name ".*history" -o -name ".bash_history" -o -name ".zsh_history" \) -exec cp -p --parents {} "${CASE_DIR}/03_users_access/histories/" \; 2>/dev/null

# ------------------------------------------------------------------------------
# 4. PERSISTENCE MECHANISMS
# ------------------------------------------------------------------------------
log_msg "[+] Phase 4: Harvesting persistence vectors..."
run_triage "Systemd services" "${CASE_DIR}/04_persistence/systemd_unit_files.txt" systemctl list-unit-files --type=service --state=enabled,generated
run_triage "Systemd timers" "${CASE_DIR}/04_persistence/systemd_timers.txt" systemctl list-timers --all
run_triage "Cron schedules" "${CASE_DIR}/04_persistence/crontabs.txt" sh -c "ls -la /etc/cron* /var/spool/cron/crontabs; head -n 100 /etc/cron*/* 2>/dev/null"
run_triage "Init.d scripts" "${CASE_DIR}/04_persistence/init_d_listing.txt" ls -latr /etc/init.d/

# ------------------------------------------------------------------------------
# 5. FILESYSTEM ANOMALIES & INTEGRITY
# ------------------------------------------------------------------------------
log_msg "[+] Phase 5: Scanning filesystem for anomalous attributes..."
run_triage "SUID/SGID Binaries" "${CASE_DIR}/05_filesystem/suid_sgid_binaries.txt" find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} \;
run_triage "Modified system binaries (Last 7 Days)" "${CASE_DIR}/05_filesystem/recent_modified_binaries.txt" find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /etc -xdev -type f -mtime -7 -ls
run_triage "Mounted storage" "${CASE_DIR}/05_filesystem/mounts_df.txt" mount
run_triage "Deleted unlinked open descriptors" "${CASE_DIR}/05_filesystem/unlinked_open_files.txt" lsof +L1

# ------------------------------------------------------------------------------
# 6. LOGS & TAMPERING EVIDENCE
# ------------------------------------------------------------------------------
log_msg "[+] Phase 6: Collecting system event journals and logs..."
if command -v journalctl >/dev/null 2>&1; then
    run_triage "Journalctl logs" "${CASE_DIR}/06_logs_configs/journalctl_triage.txt" journalctl -xb --lines=15000
fi

cp -p /var/log/audit/audit.log "${CASE_DIR}/06_logs_configs/" 2>/dev/null || true
cp -p /var/log/auth.log* "${CASE_DIR}/06_logs_configs/" 2>/dev/null || true
cp -p /var/log/secure* "${CASE_DIR}/06_logs_configs/" 2>/dev/null || true

# ------------------------------------------------------------------------------
# MANIFEST & PACKAGING
# ------------------------------------------------------------------------------
log_msg "[*] Generating cryptographic SHA-256 evidence manifest..."
find "${CASE_DIR}" -type f -exec sha256sum {} + > "${CASE_DIR}/manifest.sha256"

TARBALL="${CASE_DIR}.tar.gz"
log_msg "[*] Compressing artifacts into: ${TARBALL}"
tar -czf "${TARBALL}" -C "$(dirname "${CASE_DIR}")" "$(basename "${CASE_DIR}")"

log_msg "[+] Live Response complete. Archive SHA-256: $(sha256sum "${TARBALL}" | awk '{print $1}')"
