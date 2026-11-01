<#
.SYNOPSIS
    Enterprise DFIR Automated Live-Response Collector (Windows)
    Adheres to RFC 3227 Order of Volatility (Includes Memory Acquisition)
#>

[CmdletBinding()]
Param()

# Check Administrator rights
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] Must be run from an elevated PowerShell console."
    Exit 1
}

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$TargetHost = $env:COMPUTERNAME
$TriageRoot = Join-Path -Path $PWD -ChildPath "DFIR_TRIAGE_${TargetHost}_${Timestamp}"

$SubDirs = @(
    "00_PhysicalMemory",
    "01_VolatileNetwork",
    "02_ProcessExecution",
    "03_LogonSessions",
    "04_Persistence",
    "05_FileSystemArtifacts",
    "06_EventLogs"
)

foreach ($dir in $SubDirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $TriageRoot $dir) | Out-Null
}

$LogFile = Join-Path $TriageRoot "triage_execution.log"

function Write-TriageLog {
    Param([string]$Message)
    $Entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] $Message"
    Write-Host $Entry
    Add-Content -Path $LogFile -Value $Entry
}

function Invoke-TriageDump {
    Param(
        [string]$Description,
        [string]$OutputFile,
        [scriptblock]$Command
    )
    Write-TriageLog "Executing: $Description"
    $Header = @"
================================================================================
DESCRIPTION : $Description
TIMESTAMP   : $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ssZ"))
================================================================================
"@
    Set-Content -Path $OutputFile -Value $Header
    try {
        & $Command | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    } catch {
        $_ | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    }
}

Write-TriageLog "Beginning live response triage on $TargetHost"

# ------------------------------------------------------------------------------
# 0. PHYSICAL MEMORY ACQUISITION (WinPmem)
# ------------------------------------------------------------------------------
Write-TriageLog "Phase 0: Checking for WinPmem binary for live RAM acquisition..."
$WinPmemCmd = Get-Command "winpmem.exe" -ErrorAction SilentlyContinue
if (-not $WinPmemCmd) {
    $LocalWinPmem = Join-Path $PSScriptRoot "winpmem.exe"
    if (Test-Path $LocalWinPmem) {
        $WinPmemCmd = $LocalWinPmem
    }
}

if ($WinPmemCmd) {
    $MemDumpPath = Join-Path $TriageRoot "00_PhysicalMemory\physical_memory_${TargetHost}_${Timestamp}.raw"
    Write-TriageLog "Executing WinPmem memory acquisition -> $MemDumpPath"
    & $WinPmemCmd -o "$MemDumpPath" --volume_mode 2
    if (Test-Path $MemDumpPath) {
        Write-TriageLog "Physical memory dumped successfully. Size: $((Get-Item $MemDumpPath).Length / 1GB) GB"
    }
} else {
    Write-TriageLog "winpmem.exe not found in PATH or script directory. Skipping physical RAM acquisition."
}

# ------------------------------------------------------------------------------
# 1. NETWORK TELEMETRY
# ------------------------------------------------------------------------------
Invoke-TriageDump -Description "TCP/UDP Netstat with PIDs" `
    -OutputFile (Join-Path $TriageRoot "01_VolatileNetwork\netstat_ano.txt") `
    -Command { netstat.exe -ano }

Invoke-TriageDump -Description "Routing Table" `
    -OutputFile (Join-Path $TriageRoot "01_VolatileNetwork\route_print.txt") `
    -Command { route.exe print }

Invoke-TriageDump -Description "ARP Cache" `
    -OutputFile (Join-Path $TriageRoot "01_VolatileNetwork\arp_table.txt") `
    -Command { arp.exe -a }

Invoke-TriageDump -Description "DNS Client Cache" `
    -OutputFile (Join-Path $TriageRoot "01_VolatileNetwork\dns_cache.txt") `
    -Command { Get-DnsClientCache | Select-Object Entry, Data, Type, Status }

# ------------------------------------------------------------------------------
# 2. PROCESSES & RUNNING BINARIES
# ------------------------------------------------------------------------------
Invoke-TriageDump -Description "CIM Process Listing" `
    -OutputFile (Join-Path $TriageRoot "02_ProcessExecution\running_processes.txt") `
    -Command { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate | Sort-Object ProcessId }

Invoke-TriageDump -Description "Active Windows Services" `
    -OutputFile (Join-Path $TriageRoot "02_ProcessExecution\services.txt") `
    -Command { Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId }

# ------------------------------------------------------------------------------
# 3. LOGON SESSIONS & IDENTITY
# ------------------------------------------------------------------------------
Invoke-TriageDump -Description "Logged In Users" `
    -OutputFile (Join-Path $TriageRoot "03_LogonSessions\logged_on_users.txt") `
    -Command { quser.exe }

Invoke-TriageDump -Description "Local Administrators" `
    -OutputFile (Join-Path $TriageRoot "03_LogonSessions\local_admins.txt") `
    -Command { Get-LocalGroupMember -Group "Administrators" }

# ------------------------------------------------------------------------------
# 4. PERSISTENCE
# ------------------------------------------------------------------------------
Invoke-TriageDump -Description "Scheduled Tasks" `
    -OutputFile (Join-Path $TriageRoot "04_Persistence\scheduled_tasks.txt") `
    -Command { Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{Name="Action";Expression={$_.Actions.Execute}} }

Invoke-TriageDump -Description "Run/RunOnce Registry Keys" `
    -OutputFile (Join-Path $TriageRoot "04_Persistence\registry_run_keys.txt") `
    -Command {
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }

# ------------------------------------------------------------------------------
# 5. HIGH-VALUE EVTX EXPORTS
# ------------------------------------------------------------------------------
Write-TriageLog "Exporting Event Log channels..."
$EvtxDest = Join-Path $TriageRoot "06_EventLogs"
$Channels = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")
foreach ($ch in $Channels) {
    $CleanName = $ch.Replace("/", "_")
    $OutPath = Join-Path $EvtxDest "$CleanName.evtx"
    try {
        wevtutil.exe epl "$ch" "$OutPath"
    } catch {
        Write-TriageLog "Failed to export channel: $ch"
    }
}

# ------------------------------------------------------------------------------
# 6. MANIFEST CREATION
# ------------------------------------------------------------------------------
Write-TriageLog "Calculating SHA-256 checksums across collected evidence..."
$ManifestPath = Join-Path $TriageRoot "manifest.sha256"
Get-ChildItem -Path $TriageRoot -Recurse -File | 
    Where-Object { $_.FullName -ne $ManifestPath } | 
    ForEach-Object {
        $Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        "$Hash  $($_.FullName.Replace($TriageRoot, ''))"
    } | Out-File -FilePath $ManifestPath -Encoding UTF8

Write-TriageLog "Live Response completed. Output saved to: $TriageRoot"
