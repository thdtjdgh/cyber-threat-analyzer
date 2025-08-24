#Requires -Version 2.0
<#
.SYNOPSIS
  Windows Incident Response Collector (Clean Full Version)

.DESCRIPTION
  Collects system, process, network, autostart, event log, and filesystem artifacts.
  Generates JSON and HTML reports. Designed to run on PowerShell 2.0+ (best on 5+).

.PARAMETER OutputPath
  Output directory (default: .)

.PARAMETER AnalysisScope
  Quick | Standard | Deep (Deep currently equals Standard)

.PARAMETER TimeRange
  Days to look back (default: 7)

.PARAMETER GenerateReport
  Switch to create HTML report
#>

[CmdletBinding()]
param(
  [string]$OutputPath = ".",
  [ValidateSet("Quick","Standard","Deep")] [string]$AnalysisScope = "Standard",
  [int]$TimeRange = 7,
  [switch]$GenerateReport
)

# ---------- Globals ----------
$script:StartTime  = Get-Date
$script:Errors     = @()

# ---------- Utils ----------
function Write-Log {
  param([string]$Message, [string]$Level = "INFO")
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts] [$Level] $Message"
  Write-Host $line
  try {
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $log = Join-Path $OutputPath "analysis.log"
    Add-Content -Path $log -Value $line
  } catch {}
}

function Test-HasCmd { param([string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Get-MainModulePath {
  param([System.Diagnostics.Process]$Process)
  try { return $Process.MainModule.FileName } catch { return "Access Denied" }
}

function Parse-Netstat {
  # Fallback for PS2/Servers without Get-NetTCPConnection
  $lines = netstat -ano 2>$null | Where-Object { $_ -match "^(TCP|UDP)" }
  $out = @()
  foreach ($line in $lines) {
    $t = ($line -replace "\s+", " ").Trim().Split(" ")
    if ($t.Count -lt 4) { continue }
    $proto = $t[0]
    $local = $t[1]
    $remote = $t[2]
    $state = if ($proto -eq "UDP") { "Listen" } else { if ($t.Count -ge 4) { $t[3] } else { "" } }
    $pid   = if ($proto -eq "UDP") { if ($t.Count -ge 4) { $t[3] } else { $null } } else { if ($t.Count -ge 5) { $t[4] } else { $null } }

    # assign individually (PowerShell doesn't support multi-assign like $a="",$b="")
    $la = ""
    $lp = ""
    $ra = ""
    $rp = ""

    if ($local -match "^\[?([^\]]+)\]?:(\d+)$")  { $la = $matches[1]; $lp = [int]$matches[2] }
    if ($remote -match "^\[?([^\]]+)\]?:(\d+)$") { $ra = $matches[1]; $rp = [int]$matches[2] }

    $out += [PSCustomObject]@{
      Protocol      = $proto
      LocalAddress  = $la
      LocalPort     = $lp
      RemoteAddress = $ra
      RemotePort    = $rp
      State         = $state
      OwningProcess = if ($pid) { [int]$pid } else { $null }
    }
  }
  return $out
}

# ---------- System Info ----------
function Get-SystemBasicInfo {
  Write-Log "Collecting system info"
  $info = @{}
  try {
    $ci = Get-ComputerInfo -ErrorAction SilentlyContinue
    if ($ci) {
      $mem = $null; try { $mem = [math]::Round($ci.CsTotalPhysicalMemory/1GB,2) } catch {}
      $arch = $null; try { $arch = $ci.CsProcessors[0].Architecture } catch { $arch = $ci.OsArchitecture }
      $info.OS = @{
        ProductName = $ci.WindowsProductName
        Version     = $ci.WindowsVersion
        BuildNumber = $ci.WindowsBuildNumber
        Architecture= $arch
        InstallDate = $ci.WindowsInstallDateFromRegistry
        LastBootUpTime = $ci.CsLastBootUpTime
        TotalPhysicalMemoryGB = $mem
      }
    } else {
      $os = Get-WmiObject -Class Win32_OperatingSystem
      $mem = $null; try { $mem = [math]::Round($os.TotalVisibleMemorySize/1MB,2) } catch {}
      $info.OS = @{
        ProductName = $os.Caption
        Version     = $os.Version
        Architecture= $os.OSArchitecture
        InstallDate = $os.InstallDate
        LastBootUpTime = $os.LastBootUpTime
        TotalPhysicalMemoryGB = $mem
      }
    }

    $hotfixes = @(); try { $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending } catch {}
    $recent = @()
    foreach ($hf in ($hotfixes | Select-Object -First 10)) {
      $recent += @{ HotFixID=$hf.HotFixID; Description=$hf.Description; InstalledOn=$hf.InstalledOn; InstalledBy=$hf.InstalledBy }
    }
    $last = $null; try { $last = ($hotfixes | Select-Object -First 1).InstalledOn } catch {}
    $info.SecurityPatches = @{ TotalCount=$hotfixes.Count; RecentPatches=$recent; LastPatchDate=$last }

    if (Test-HasCmd "Get-LocalUser") {
      $info.UserAccounts = @(Get-LocalUser | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Enabled=$_.Enabled; LastLogon=$_.LastLogon; PasswordLastSet=$_.PasswordLastSet }
      })
    } else {
      $info.UserAccounts = @(Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Disabled=$_.Disabled; Lockout=$_.Lockout }
      })
    }

    $info.NetworkConfiguration = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
      Where-Object {$_.IPEnabled} | ForEach-Object {
        [PSCustomObject]@{
          Description=$_.Description; IPAddress=$_.IPAddress; SubnetMask=$_.IPSubnet; Gateway=$_.DefaultIPGateway;
          DNSServers=$_.DNSServerSearchOrder; DHCPEnabled=$_.DHCPEnabled; MACAddress=$_.MACAddress
        }
      })

    return $info
  } catch {
    Write-Log "System info error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "SystemInfo: $($_.Exception.Message)"
    return $null
  }
}

# ---------- Process & Services ----------
function Get-ProcessAnalysis {
  param([int]$Days = 7)
  Write-Log "Analyzing processes"
  $analysis = @{}
  try {
    $procs = Get-Process | Sort-Object CPU -Descending
    $top = @()
    foreach ($p in ($procs | Select-Object -First 10)) {
      # compute values outside of hashtable
      $wsMB = $null
      try { $wsMB = [math]::Round(($p.WorkingSet)/1MB, 2) } catch { $wsMB = $null }

      $top += @{
        Name          = $p.ProcessName
        PID           = $p.Id
        CPU           = $p.CPU
        WorkingSetMB  = $wsMB
        StartTime     = $p.StartTime
        Path          = (Get-MainModulePath -Process $p)
      }
    }
    $analysis.ProcessSummary = @{
      TotalProcesses  = $procs.Count
      TopCPUProcesses = $top
    }

    # Suspicious heuristics
    $sus = @()
    foreach ($p in $procs) {
      $flag = $false
      $reasons = @()

      try {
        if ($p.ProcessName -match '^(svchost|explorer|winlogon|csrss|lsass)$') {
          $pp = Get-MainModulePath -Process $p
          if ($pp -and ($pp -notlike "$env:SystemRoot\System32\*" -and $pp -notlike "$env:SystemRoot\SysWOW64\*")) {
            $flag = $true; $reasons += "core process in non-system path"
          }
        }
        $path = Get-MainModulePath -Process $p
        if ($path -and $path -ne "Access Denied") {
          $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
          if ($sig -and $sig.Status -ne "Valid") { $flag = $true; $reasons += "invalid signature" }
        }
        $con=@()
        try {
          if (Test-HasCmd "Get-NetTCPConnection") {
            $con = Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue
          } else {
            $all = Parse-Netstat
            $con = $all | Where-Object { $_.OwningProcess -eq $p.Id }
          }
        } catch {}
        if ($con -and $con.Count -gt 10) { $flag = $true; $reasons += "too many TCP connections ($($con.Count))" }
      } catch {}

      if ($flag) {
        $sus += @{
          Name      = $p.ProcessName
          PID       = $p.Id
          Path      = (Get-MainModulePath -Process $p)
          StartTime = $p.StartTime
          Reasons   = $reasons
        }
      }
    }
    $analysis.SuspiciousProcesses = $sus

    $svcs = Get-Service
    $analysis.ServicesSummary = @{
      Total   = $svcs.Count
      Running = ($svcs | Where-Object {$_.Status -eq 'Running'}).Count
      Stopped = ($svcs | Where-Object {$_.Status -eq 'Stopped'}).Count
    }

    # Recently modified services by registry LastWrite
    $recent=@()
    $root = "HKLM:\SYSTEM\CurrentControlSet\Services"
    try {
      $th = (Get-Date).AddDays(-$Days)
      foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        if ($k.LastWriteTime -gt $th) {
          $svc = $null; try { $svc = Get-Service $k.PSChildName -ErrorAction SilentlyContinue } catch {}
          if ($svc) {
            $recent += @{ Name=$k.PSChildName; DisplayName=$svc.DisplayName; Status=$svc.Status; Modified=$k.LastWriteTime }
          }
        }
      }
    } catch {}
    $analysis.RecentServices = $recent

    Write-Log ("Process analysis complete - suspicious: {0}" -f $sus.Count)
    return $analysis
  } catch {
    Write-Log "Process analysis error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "ProcessAnalysis: $($_.Exception.Message)"
    return $null
  }
}

# ---------- Network ----------
function Get-NetworkAnalysis {
  Write-Log "Analyzing network"
  $analysis = @{}
  try {
    $tcp=@()
    if (Test-HasCmd "Get-NetTCPConnection") {
      $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
    } else {
      $tcp = Parse-Netstat
    }

    $est = @($tcp | Where-Object { $_.State -eq "Established" })
    $lst = @($tcp | Where-Object { $_.State -match "Listen" })

    $analysis.NetworkConnections = @{
      TotalTCPConnections    = $tcp.Count
      EstablishedConnections = $est.Count
      ListeningPortsCount    = $lst.Count
    }

    $badPorts = 6667,6668,6669,7000,8080,4444,5555,31337
    $sus=@()
    foreach ($c in $est) {
      $reasons=@()
      if ($c.RemotePort -in $badPorts) { $reasons += "known bot/backdoor port" }
      $isPrivate = $false
      $ra = $c.RemoteAddress
      if ($ra -match "^(10\.|192\.168\.|127\.)") { $isPrivate=$true }
      if ($ra -match "^172\.(1[6-9]|2[0-9]|3[01])\.") { $isPrivate=$true }
      if (-not $isPrivate -and $ra -ne "0.0.0.0" -and $ra -ne "::") {
        $pname="Unknown"; try { $pname=(Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
        if ($pname -notin @("chrome","firefox","iexplore","outlook","teams","edge","msedge")) { $reasons += "external conn by uncommon process" }
      }
      if ($reasons.Count -gt 0) {
        $sus += @{
          LocalAddress=$c.LocalAddress; LocalPort=$c.LocalPort; RemoteAddress=$c.RemoteAddress; RemotePort=$c.RemotePort;
          State=$c.State; ProcessName=(try {(Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName} catch {"Unknown"});
          PID=$c.OwningProcess; Reasons=$reasons
        }
      }
    }
    $analysis.SuspiciousConnections = $sus

    $lp=@()
    foreach ($l in $lst) {
      $pn="Unknown"; try { $pn=(Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
      $lp += @{ Port=$l.LocalPort; Address=$l.LocalAddress; ProcessName=$pn; PID=$l.OwningProcess }
    }
    $analysis.ListeningPorts = $lp | Sort-Object Port

    Write-Log ("Network analysis complete - suspicious connections: {0}" -f $sus.Count)
    return $analysis
  } catch {
    Write-Log "Network analysis error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "NetworkAnalysis: $($_.Exception.Message)"
    return $null
  }
}

# ---------- Autostart ----------
function Get-AutostartAnalysis {
  Write-Log "Analyzing autostart"
  $analysis=@{}
  $items=@()

  try {
    $runKeys = @(
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($k in $runKeys) {
      try {
        $props = Get-ItemProperty -Path $k -ErrorAction Stop
        foreach ($p in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
          $items += @{ Location=$k; Name=$p.Name; Command=$p.Value; Type="Registry" }
        }
      } catch {}
    }

    $autos = @(Get-Service | Where-Object {$_.StartType -eq "Automatic"})
    foreach ($s in $autos) {
      $path = $null
      try {
        $ws = Get-WmiObject -Class Win32_Service -Filter ("Name='{0}'" -f $s.Name) -ErrorAction SilentlyContinue
        if ($ws) { $path = $ws.PathName }
      } catch {}
      $items += @{ Location="Services"; Name=$s.Name; Command=$path; Type="Service"; Status=$s.Status }
    }

    $startupFolders = @(
      "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
      "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($f in $startupFolders) {
      try {
        if (Test-Path $f) {
          foreach ($it in (Get-ChildItem $f -ErrorAction SilentlyContinue)) {
            $items += @{ Location=$f; Name=$it.Name; Command=$it.FullName; Type="StartupFolder" }
          }
        }
      } catch {}
    }

    if (Test-HasCmd "Get-ScheduledTask") {
      foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $exe=$null; $state=$null
        try { $exe=$t.Actions.Execute -join ";" } catch {}
        try { $state=$t.State } catch {}
        $items += @{ Location="TaskScheduler"; Name=$t.TaskName; Command=$exe; Type="ScheduledTask"; State=$state }
      }
    }

    $analysis.AutostartItems = $items
    $analysis.Summary = @{
      TotalItems=$items.Count
      RegistryItems=($items | Where-Object {$_.Type -eq "Registry"}).Count
      Services=($items | Where-Object {$_.Type -eq "Service"}).Count
      StartupFolderItems=($items | Where-Object {$_.Type -eq "StartupFolder"}).Count
      ScheduledTasks=($items | Where-Object {$_.Type -eq "ScheduledTask"}).Count
    }
    Write-Log ("Autostart analysis complete - items: {0}" -f $items.Count)
    return $analysis
  } catch {
    Write-Log "Autostart analysis error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "Autostart: $($_.Exception.Message)"
    return $null
  }
}

# ---------- Event Logs ----------
function Get-EventLogAnalysis {
  param([int]$Days = 7)
  Write-Log "Analyzing event logs (last $Days days)"
  $analysis=@{}
  $start=(Get-Date).AddDays(-$Days)
  try {
    $sec=@()
    if (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue) {
      $f4625=@(); try { $f4625 = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$start} -ErrorAction SilentlyContinue } catch {}
      if ($f4625) {
        $evs=@()
        foreach ($e in ($f4625 | Select-Object -First 10)) { $evs += @{ TimeCreated=$e.TimeCreated; ID=$e.Id; Message=$e.Message } }
        $sec += @{ Type="Failed Logons (4625)"; Count=$f4625.Count; Events=$evs }
      }
      $s4624=@(); try { $s4624 = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$start} -ErrorAction SilentlyContinue } catch {}
      if ($s4624) {
        $rec=@()
        foreach ($e in ($s4624 | Select-Object -First 5)) { $rec += @{ TimeCreated=$e.TimeCreated; ID=$e.Id } }
        $sec += @{ Type="Successful Logons (4624)"; Count=$s4624.Count; RecentEvents=$rec }
      }
    }
    $analysis.SecurityEvents=$sec

    $sys=@()
    $errs=@(); try { $errs = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=$start} -ErrorAction SilentlyContinue } catch {}
    if ($errs) {
      $top=@()
      foreach ($g in ($errs | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5)) {
        $msg=$null; $lvl=$null
        try { $msg=$g.Group[0].Message; $lvl=$g.Group[0].LevelDisplayName } catch {}
        $sample = if ($msg) { "{0}: {1}" -f $lvl, ($msg.Substring(0, [Math]::Min(100,$msg.Length))) } else { $null }
        $top += @{ EventID=$g.Name; Count=$g.Count; Sample=$sample }
      }
      $sys += @{ Type="System Errors/Warnings (L1-3)"; Count=$errs.Count; TopEvents=$top }
    }
    $analysis.SystemEvents=$sys

    $psSumm=$null
    try {
      $ps = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$start} -ErrorAction SilentlyContinue
      if ($ps) {
        $recent=@()
        foreach ($e in ($ps | Where-Object {$_.Id -eq 4104} | Select-Object -First 10)) {
          $txt=$e.Message
          try {
            if ($e.Properties.Count -ge 3 -and $e.Properties[2].Value) { $txt=[string]$e.Properties[2].Value }
          } catch {}
          $recent += @{ TimeCreated=$e.TimeCreated; ScriptBlock=$txt }
        }
        $psSumm=@{ TotalEvents=$ps.Count; RecentCommands=$recent }
      }
    } catch {}
    if ($psSumm) { $analysis.PowerShellEvents=$psSumm }

    Write-Log "Event log analysis complete"
    return $analysis
  } catch {
    Write-Log "Event log analysis error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "EventLog: $($_.Exception.Message)"
    return $null
  }
}

# ---------- File System ----------
function Get-FileSystemAnalysis {
  param([int]$Days = 7)
  Write-Log "Analyzing file system (last $Days days)"
  $analysis=@{}
  $start=(Get-Date).AddDays(-$Days)
  try {
    $paths = @("$env:SystemRoot\System32","$env:SystemRoot\SysWOW64","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA")

    $recent=@()
    foreach ($p in $paths) {
      try {
        if (Test-Path $p) {
          $files = Get-ChildItem $p -Recurse -Include "*.exe","*.dll","*.scr","*.com" -ErrorAction SilentlyContinue
          foreach ($f in ($files | Where-Object { $_.CreationTime -gt $start -or $_.LastWriteTime -gt $start })) {
            $recent += @{ Path=$f.FullName; Name=$f.Name; CreationTime=$f.CreationTime; LastWriteTime=$f.LastWriteTime; Size=$f.Length; Directory=$f.DirectoryName }
          }
        }
      } catch {}
    }
    $analysis.RecentExecutables = $recent | Sort-Object CreationTime -Descending

    $suspExt = @("*.vbs","*.bat","*.cmd","*.ps1","*.jar","*.scr")
    $susp=@()
    foreach ($p in $paths) {
      try {
        if (Test-Path $p) {
          foreach ($e in $suspExt) {
            $ff = Get-ChildItem $p -Recurse -Include $e -ErrorAction SilentlyContinue
            foreach ($f in ($ff | Where-Object { $_.CreationTime -gt $start })) {
              $susp += @{ Path=$f.FullName; Extension=$f.Extension; CreationTime=$f.CreationTime; Size=$f.Length }
            }
          }
        }
      } catch {}
    }
    $analysis.SuspiciousFiles=$susp

    $tempDirs=@($env:TEMP,"$env:SystemRoot\Temp","$env:LOCALAPPDATA\Temp")
    $temp=@()
    foreach ($td in $tempDirs) {
      try {
        if (Test-Path $td) {
          $tfiles=@(Get-ChildItem $td -ErrorAction SilentlyContinue)
          $sum=0; try { $sum = ($tfiles | Measure-Object Length -Sum).Sum } catch { $sum=0 }
          $recentT=@()
          foreach ($f in ($tfiles | Where-Object { $_.CreationTime -gt $start } | Select-Object -First 10)) {
            $recentT += @{ Name=$f.Name; CreationTime=$f.CreationTime; Size=$f.Length }
          }
          $temp += @{ Path=$td; FileCount=$tfiles.Count; TotalSize=$sum; RecentFiles=$recentT }
        }
      } catch {}
    }
    $analysis.TempDirectories=$temp

    Write-Log ("File system analysis complete - recent executables: {0}, suspicious files: {1}" -f $recent.Count, $susp.Count)
    return $analysis
  } catch {
    Write-Log "File system analysis error: $($_.Exception.Message)" "ERROR"
    $script:Errors += "FileSystem: $($_.Exception.Message)"
    return $null
  }
}

# ---------- Report ----------
function Generate-Report {
  param($Results, $OutputPath)
  Write-Log "Generating report"

  try {
    $Results | ConvertTo-Json -Depth 12 | Out-File (Join-Path $OutputPath "analysis_results.json") -Encoding UTF8
  } catch { Write-Log "JSON write failed: $($_.Exception.Message)" "ERROR"; $script:Errors += "Report(JSON): $($_.Exception.Message)" }

  $enc = [System.Web.HttpUtility]
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8" /><title>Windows Incident Response Report</title>')
  $null = $sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px}.header{background:#2c3e50;color:#fff;padding:20px;border-radius:8px}.section{margin-top:20px;border:1px solid #ddd;padding:15px;border-radius:8px}.warning{background:#f39c12;color:#fff;padding:10px;border-radius:6px}.error{background:#e74c3c;color:#fff;padding:10px;border-radius:6px}.info{background:#3498db;color:#fff;padding:10px;border-radius:6px}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{border:1px solid #eee;padding:8px;text-align:left}th{background:#f7f7f7}.suspicious{background:#ffefef}.muted{color:#666}code{background:#f0f0f0;padding:2px 4px;border-radius:4px}</style></head><body>')
  $null = $sb.AppendLine('<div class="header"><h1>Windows Incident Response Report</h1>')
  $null = $sb.AppendLine(("</p><p>Generated: {0}</p>" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")))
  $null = $sb.AppendLine(("</p><p>Scope: {0} | Days: {1}</p></div>" -f $Results.AnalysisMetadata.Scope, $Results.AnalysisMetadata.TimeRange))

  if ($Results.SystemInfo) {
    $os=$Results.SystemInfo.OS; $sec=$Results.SystemInfo.SecurityPatches
    $null=$sb.AppendLine('<div class="section"><h2>System Information</h2><table>')
    $null=$sb.AppendLine(("  <tr><th>Product</th><td>{0}</td></tr>" -f $enc::HtmlEncode([string]$os.ProductName)))
    $null=$sb.AppendLine(("  <tr><th>Version</th><td>{0} (Build {1})</td></tr>" -f $enc::HtmlEncode([string]$os.Version), $enc::HtmlEncode([string]$os.BuildNumber)))
    $null=$sb.AppendLine(("  <tr><th>Architecture</th><td>{0}</td></tr>" -f $enc::HtmlEncode([string]$os.Architecture)))
    $null=$sb.AppendLine(("  <tr><th>Install Date</th><td>{0}</td></tr>" -f $os.InstallDate))
    $null=$sb.AppendLine(("  <tr><th>Last Boot</th><td>{0}</td></tr>" -f $os.LastBootUpTime))
    $null=$sb.AppendLine(("  <tr><th>Total Memory(GB)</th><td>{0}</td></tr>" -f $os.TotalPhysicalMemoryGB))
    $null=$sb.AppendLine(("  <tr><th>Hotfix Count</th><td>{0}</td></tr>" -f $sec.TotalCount))
    $null=$sb.AppendLine(("  <tr><th>Last Patch Date</th><td>{0}</td></tr>" -f $sec.LastPatchDate))
    $null=$sb.AppendLine('</table></div>')
  }

  if ($Results.ProcessAnalysis) {
    $pa=$Results.ProcessAnalysis
    $null=$sb.AppendLine('<div class="section"><h2>Process Analysis</h2>')
    $null=$sb.AppendLine(("  <p>Total processes: {0}</p>" -f $pa.ProcessSummary.TotalProcesses))
    if ($pa.SuspiciousProcesses -and $pa.SuspiciousProcesses.Count -gt 0) {
      $null=$sb.AppendLine('  <div class="warning">Suspicious processes found.</div>')
      $null=$sb.AppendLine('  <table><tr><th>Process</th><th>PID</th><th>Path</th><th>Start</th><th>Reasons</th></tr>')
      foreach ($p in $pa.SuspiciousProcesses) {
        $null=$sb.AppendLine(("    <tr class=""suspicious""><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f
          $enc::HtmlEncode([string]$p.Name), $p.PID, $enc::HtmlEncode([string]$p.Path), $p.StartTime, $enc::HtmlEncode(([string]($p.Reasons -join ', ')))))
      }
      $null=$sb.AppendLine('  </table>')
    } else { $null=$sb.AppendLine('  <div class="info">No suspicious process found.</div>') }
    $null=$sb.AppendLine('</div>')
  }

  if ($Results.NetworkAnalysis) {
    $na=$Results.NetworkAnalysis
    $null=$sb.AppendLine('<div class="section"><h2>Network Analysis</h2>')
    $null=$sb.AppendLine(("  <p>Total TCP: {0} | Established: {1} | Listening: {2}</p>" -f $na.NetworkConnections.TotalTCPConnections, $na.NetworkConnections.EstablishedConnections, $na.NetworkConnections.ListeningPortsCount))
    if ($na.SuspiciousConnections -and $na.SuspiciousConnections.Count -gt 0) {
      $null=$sb.AppendLine('  <div class="warning">Suspicious connections found.</div>')
      $null=$sb.AppendLine('  <table><tr><th>Local</th><th>Remote</th><th>State</th><th>Process</th><th>Reasons</th></tr>')
      foreach ($c in $na.SuspiciousConnections) {
        $null=$sb.AppendLine(("    <tr class=""suspicious""><td>{0}:{1}</td><td>{2}:{3}</td><td>{4}</td><td>{5} (PID {6})</td><td>{7}</td></tr>" -f
          $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State,
          $enc::HtmlEncode([string]$c.ProcessName), $c.PID, $enc::HtmlEncode(([string]($c.Reasons -join ', ')))))
      }
      $null=$sb.AppendLine('  </table>')
    } else { $null=$sb.AppendLine('  <div class="info">No suspicious connections found.</div>') }
    if ($na.ListeningPorts -and $na.ListeningPorts.Count -gt 0) {
      $null=$sb.AppendLine('  <h3>Listening Ports</h3><table><tr><th>Port</th><th>Address</th><th>Process</th><th>PID</th></tr>')
      foreach ($l in $na.ListeningPorts) {
        $null=$sb.AppendLine(("    <tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>" -f $l.Port, $l.Address, $enc::HtmlEncode([string]$l.ProcessName), $l.PID))
      }
      $null=$sb.AppendLine('  </table>')
    }
    $null=$sb.AppendLine('</div>')
  }

  if ($Results.AutostartAnalysis) {
    $aa=$Results.AutostartAnalysis
    $null=$sb.AppendLine('<div class="section"><h2>Autostart (Persistence)</h2>')
    $null=$sb.AppendLine(("  <p>Total: {0} | Registry: {1} | Services: {2} | StartupFolder: {3} | ScheduledTasks: {4}</p>" -f
      $aa.Summary.TotalItems, $aa.Summary.RegistryItems, $aa.Summary.Services, $aa.Summary.StartupFolderItems, $aa.Summary.ScheduledTasks))
    if ($aa.AutostartItems -and $aa.AutostartItems.Count -gt 0) {
      $null=$sb.AppendLine('  <table><tr><th>Type</th><th>Name</th><th>Command</th><th>Location</th></tr>')
      foreach ($i in ($aa.AutostartItems | Select-Object -First 50)) {
        $null=$sb.AppendLine(("    <tr><td>{0}</td><td>{1}</td><td><code>{2}</code></td><td class=""muted"">{3}</td></tr>" -f
          $enc::HtmlEncode([string]$i.Type), $enc::HtmlEncode([string]$i.Name), $enc::HtmlEncode([string]$i.Command), $enc::HtmlEncode([string]$i.Location)))
      }
      $null=$sb.AppendLine('  </table><p class="muted">* Showing up to 50 items. See JSON for full list.</p>')
    } else { $null=$sb.AppendLine('  <div class="info">No autostart items.</div>') }
    $null=$sb.AppendLine('</div>')
  }

  if ($Results.EventLogAnalysis) {
    $ev=$Results.EventLogAnalysis
    $null=$sb.AppendLine('<div class="section"><h2>Event Logs</h2>')
    if ($ev.SecurityEvents) {
      foreach ($s in $ev.SecurityEvents) {
        $null=$sb.AppendLine(("  <h3>{0} — Count {1}</h3>" -f $enc::HtmlEncode([string]$s.Type), $s.Count))
        if ($s.Events) {
          $null=$sb.AppendLine('  <table><tr><th>Time</th><th>ID</th><th>Message</th></tr>')
          foreach ($e in $s.Events) {
            $null=$sb.AppendLine(("    <tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f $e.TimeCreated, $e.ID, $enc::HtmlEncode([string]$e.Message)))
          }
          $null=$sb.AppendLine('  </table>')
        }
        if ($s.RecentEvents) {
          $null=$sb.AppendLine('  <table><tr><th>Time</th><th>ID</th></tr>')
          foreach ($e in $s.RecentEvents) {
            $null=$sb.AppendLine(("    <tr><td>{0}</td><td>{1}</td></tr>" -f $e.TimeCreated, $e.ID))
          }
          $null=$sb.AppendLine('  </table>')
        }
      }
    }
    if ($ev.SystemEvents) {
      foreach ($se in $ev.SystemEvents) {
        $null=$sb.AppendLine(("  <h3>{0} — Count {1}</h3>" -f $enc::HtmlEncode([string]$se.Type), $se.Count))
        if ($se.TopEvents) {
          $null=$sb.AppendLine('  <table><tr><th>EventID</th><th>Count</th><th>Sample</th></tr>')
          foreach ($te in $se.TopEvents) {
            $null=$sb.AppendLine(("    <tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f $te.EventID, $te.Count, $enc::HtmlEncode([string]$te.Sample)))
          }
          $null=$sb.AppendLine('  </table>')
        }
      }
    }
    if ($ev.PowerShellEvents) {
      $null=$sb.AppendLine('  <h3>PowerShell Operational</h3>')
      $null=$sb.AppendLine(("  <p>Total: {0}</p>" -f $ev.PowerShellEvents.TotalEvents))
      if ($ev.PowerShellEvents.RecentCommands) {
        $null=$sb.AppendLine('  <table><tr><th>Time</th><th>ScriptBlock (truncated)</th></tr>')
        foreach ($rc in $ev.PowerShellEvents.RecentCommands) {
          $txt=[string]$rc.ScriptBlock
          if ($txt) { $txt = $txt.Substring(0,[Math]::Min(200,$txt.Length)) }
          $null=$sb.AppendLine(("    <tr><td>{0}</td><td><code>{1}</code></td></tr>" -f $rc.TimeCreated, $enc::HtmlEncode($txt)))
        }
        $null=$sb.AppendLine('  </table>')
      }
    }
    $null=$sb.AppendLine('</div>')
  }

  if ($Results.AnalysisMetadata.Errors -and $Results.AnalysisMetadata.Errors.Count -gt 0) {
    $null=$sb.AppendLine('<div class="section"><h2>Errors during analysis</h2>')
    foreach ($er in $Results.AnalysisMetadata.Errors) { $null=$sb.AppendLine(("  <div class=""error"">{0}</div>" -f $enc::HtmlEncode([string]$er))) }
    $null=$sb.AppendLine('</div>')
  }

  $null=$sb.AppendLine('<div class="section"><h2>Run Metadata</h2>')
  $null=$sb.AppendLine(("  <p>Start: {0}</p>" -f $Results.AnalysisMetadata.StartTime))
  $null=$sb.AppendLine(("  <p>End: {0}</p>" -f $Results.AnalysisMetadata.EndTime))
  $null=$sb.AppendLine(("  <p>Duration: {0}</p>" -f $Results.AnalysisMetadata.Duration.ToString("hh\:mm\:ss")))
  $null=$sb.AppendLine('</div>')

  $null=$sb.AppendLine('</body></html>')
  try {
    $sb.ToString() | Out-File (Join-Path $OutputPath "analysis_report.html") -Encoding UTF8
    Write-Log "Report written: analysis_report.html"
  } catch { Write-Log "HTML write failed: $($_.Exception.Message)" "ERROR"; $script:Errors += "Report(HTML): $($_.Exception.Message)" }
}

# ---------- Orchestrator ----------
function Start-IncidentAnalysis {
  param([string]$Scope,[int]$TimeRange)
  Write-Log ("Starting analysis - scope={0}, days={1}" -f $Scope, $TimeRange)
  $r=@{}
  $r.SystemInfo      = Get-SystemBasicInfo
  $r.ProcessAnalysis = Get-ProcessAnalysis -Days $TimeRange
  $r.NetworkAnalysis = Get-NetworkAnalysis
  if ($Scope -in @("Standard","Deep")) {
    $r.AutostartAnalysis = Get-AutostartAnalysis
    $r.EventLogAnalysis  = Get-EventLogAnalysis -Days $TimeRange
    $r.FileSystemAnalysis= Get-FileSystemAnalysis -Days $TimeRange
  }
  if ($Scope -eq "Deep") { Write-Log "Deep mode: additional modules can be added in future builds" }
  $r.AnalysisMetadata = @{
    StartTime = $script:StartTime
    EndTime   = Get-Date
    Duration  = (Get-Date) - $script:StartTime
    Scope     = $Scope
    TimeRange = $TimeRange
    Errors    = $script:Errors
  }
  return $r
}

# ---------- Main ----------
try {
  if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
  Write-Log ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)
  $res = Start-IncidentAnalysis -Scope $AnalysisScope -TimeRange $TimeRange
  $res | ConvertTo-Json -Depth 12 | Out-File (Join-Path $OutputPath "analysis_results.json") -Encoding UTF8
  if ($GenerateReport) { Generate-Report -Results $res -OutputPath $OutputPath }

  Write-Host "`n=== Summary ===" -ForegroundColor Green
  if ($res.ProcessAnalysis -and $res.ProcessAnalysis.SuspiciousProcesses.Count -gt 0) { Write-Host "⚠ Suspicious processes: $($res.ProcessAnalysis.SuspiciousProcesses.Count)" -ForegroundColor Yellow } else { Write-Host "✔ No suspicious processes" -ForegroundColor Green }
  if ($res.NetworkAnalysis -and $res.NetworkAnalysis.SuspiciousConnections.Count -gt 0) { Write-Host "⚠ Suspicious connections: $($res.NetworkAnalysis.SuspiciousConnections.Count)" -ForegroundColor Yellow } else { Write-Host "✔ No suspicious connections" -ForegroundColor Green }
  if ($script:Errors.Count -gt 0) { Write-Host "❌ Errors: $($script:Errors.Count) (see analysis.log)" -ForegroundColor Red }
  Write-Host "Output saved to '$OutputPath'" -ForegroundColor Green
} catch {
  Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
  Write-Host "Script failed: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
