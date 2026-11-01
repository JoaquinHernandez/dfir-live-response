# dfir-live-response
# Enterprise DFIR Automated Live-Response Framework
<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/5d9a2800-1294-4923-8021-acf92d71c38b" />


An automated incident response triage collector for Linux and Windows endpoints based on industry DFIR commands. Strictly adheres to **RFC 3227 order of volatility**, captures full volatile RAM, preserves timestamps, records stdout/stderr, and creates a SHA-256 evidence manifest for chain-of-custody preservation.

## Order of Volatility (RFC 3227)
1. **Physical Memory (RAM):** Raw dump via LiME kernel driver (Linux) or WinPmem driver (Windows).
2. **Volatile Network State:** Active sockets, listening services, routing tables, and ARP/DNS caches.
3. **Execution State:** Full process tree, command lines, environment strings, and open handles.
4. **Identity & Persistence:** Active sessions, local groups, systemd units, scheduled tasks, and Run keys.
5. **System Event Journals:** Systemd logs, auth logs, and native `.evtx` channels.
6. **Integrity Validation:** SHA-256 hash generated across every single artifact collected.

---

## Linux Usage

### Prerequisites
- Root privileges (`sudo`)
- For full physical RAM acquisition: A compiled `lime.ko` module matching `uname -r` in the working directory (optional; skipped safely if not found).

### Execution
```bash
chmod +x linux/ir_linux_triage.sh
sudo ./linux/ir_linux_triage.sh

# Enterprise DFIR Automated Live-Response Framework

An automated incident response triage collector for Linux and Windows endpoints based on industry DFIR commands. Strictly adheres to **RFC 3227 order of volatility**, captures full volatile RAM, preserves timestamps, records stdout/stderr, and creates a SHA-256 evidence manifest for chain-of-custody preservation.

## Order of Volatility (RFC 3227)
1. **Physical Memory (RAM):** Raw dump via LiME kernel driver (Linux) or WinPmem driver (Windows).
2. **Volatile Network State:** Active sockets, listening services, routing tables, and ARP/DNS caches.
3. **Execution State:** Full process tree, command lines, environment strings, and open handles.
4. **Identity & Persistence:** Active sessions, local groups, systemd units, scheduled tasks, and Run keys.
5. **System Event Journals:** Systemd logs, auth logs, and native `.evtx` channels.
6. **Integrity Validation:** SHA-256 hash generated across every single artifact collected.

---

## Linux Usage

### Prerequisites
- Root privileges (`sudo`)
- For full physical RAM acquisition: A compiled `lime.ko` module matching `uname -r` in the working directory (optional; skipped safely if not found).

### Execution
```bash
chmod +x linux/ir_linux_triage.sh
sudo ./linux/ir_linux_triage.sh

Initialize the local Git repository:

Bash
mkdir dfir-live-response
cd dfir-live-response
git init -b main
mkdir -p .github/workflows linux windows
Populate files: Save each of the 6 files into their respective paths as shown in the tree structure above.

Stage and commit the files:

Bash
git add .
git commit -m "feat: initial commit of RFC 3227 DFIR triage framework"
Push to your GitHub repository:

Bash
git remote add origin https://github.com/<YOUR-USERNAME>/<YOUR-REPO-NAME>.git
git push -u origin main
