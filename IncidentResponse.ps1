#Requires -Version 2.0
<#
.SYNOPSIS
    Windows 침해사고 대응 통합 분석 스크립트
    KISA 2010년 안내서 기반 현대화 버전

.DESCRIPTION
    이 스크립트는 KISA 2010년 침해사고 분석 절차 안내서에서 제시된
    분석 기법들을 PowerShell로 통합 구현한 도구입니다.
    
.PARAMETER OutputPath
    결과 파일을 저장할 경로 (기본값: 현재 디렉터리)
    
.PARAMETER AnalysisScope
    분석 범위 선택: 'Quick', 'Standard', 'Deep'
    
.PARAMETER TimeRange
    분석할 시간 범위 (일 단위, 기본값: 7일)
    
.EXAMPLE
    .\IncidentResponse.ps1 -AnalysisScope Standard -TimeRange 3
    
.NOTES
    Author: Security Response Team
    Version: 2.0
    Created: 2025-01-01
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [ValidateSet("Quick","Standard","Deep")]
    [string]$AnalysisScope = "Standard",
    [int]$TimeRange = 7,
    [switch]$RealTimeMonitoring,
    [switch]$GenerateReport
)

# 전역 변수 설정
$script:StartTime = Get-Date
$script:OutputPath = $OutputPath
$script:Results = @{}
$script:Errors = @()

# 로깅 함수
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path "$OutputPath\analysis.log" -Value $logMessage
}

# 시스템 기본 정보 수집 모듈
function Get-SystemBasicInfo {
    Write-Log "시스템 기본 정보 수집 시작"
    
    $info = @{}
    
    try {
        # 기본 시스템 정보
        $computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
        if ($computerInfo) {
            $info.OS = @{
                ProductName = $computerInfo.WindowsProductName
                Version = $computerInfo.WindowsVersion
                BuildNumber = $computerInfo.WindowsBuildNumber
                Architecture = $computerInfo.CsProcessors[0].Architecture
                InstallDate = $computerInfo.WindowsInstallDateFromRegistry
                LastBootUpTime = $computerInfo.CsLastBootUpTime
                TotalPhysicalMemory = [math]::Round($computerInfo.CsTotalPhysicalMemory / 1GB, 2)
            }
        } else {
            # PowerShell 2.0 호환 방식
            $os = Get-WmiObject -Class Win32_OperatingSystem
            $info.OS = @{
                ProductName = $os.Caption
                Version = $os.Version
                Architecture = $os.OSArchitecture
                InstallDate = $os.InstallDate
                LastBootUpTime = $os.LastBootUpTime
                TotalPhysicalMemory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            }
        }
        
        # 보안 패치 정보
        Write-Log "보안 패치 정보 수집 중..."
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
        $info.SecurityPatches = @{
            TotalCount = $hotfixes.Count
            RecentPatches = $hotfixes | Select-Object -First 10 | ForEach-Object {
                @{
                    HotFixID = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = $_.InstalledOn
                    InstalledBy = $_.InstalledBy
                }
            }
            LastPatchDate = ($hotfixes | Select-Object -First 1).InstalledOn
        }
        
        # 사용자 계정 정보
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $localUsers = Get-LocalUser
            $info.UserAccounts = $localUsers | ForEach-Object {
                @{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    LastLogon = $_.LastLogon
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordRequired = $_.PasswordRequired
                    UserMayChangePassword = $_.UserMayChangePassword
                }
            }
        } else {
            # WMI 방식으로 대체
            $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
            $info.UserAccounts = $users | ForEach-Object {
                @{
                    Name = $_.Name
                    Disabled = $_.Disabled
                    Lockout = $_.Lockout
                    PasswordRequired = $_.PasswordRequired
                }
            }
        }
        
        # 네트워크 설정
        $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
        $info.NetworkConfiguration = $networkAdapters | ForEach-Object {
            @{
                Description = $_.Description
                IPAddress = $_.IPAddress
                SubnetMask = $_.IPSubnet
                Gateway = $_.DefaultIPGateway
                DNSServers = $_.DNSServerSearchOrder
                DHCPEnabled = $_.DHCPEnabled
                MACAddress = $_.MACAddress
            }
        }
        
        Write-Log "시스템 기본 정보 수집 완료"
        return $info
        
    } catch {
        Write-Log "시스템 정보 수집 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "SystemInfo: $($_.Exception.Message)"
        return $null
    }
}

# 프로세스 분석 모듈
function Get-ProcessAnalysis {
    Write-Log "프로세스 분석 시작"
    
    $analysis = @{}
    
    try {
        # 실행 중인 프로세스 정보
        $processes = Get-Process | Sort-Object CPU -Descending
        
        $analysis.ProcessSummary = @{
            TotalProcesses = $processes.Count
            TopCPUProcesses = $processes | Select-Object -First 10 | ForEach-Object {
                @{
                    Name = $_.ProcessName
                    PID = $_.Id
                    CPU = $_.CPU
                    WorkingSet = [math]::Round($_.WorkingSet / 1MB, 2)
                    StartTime = $_.StartTime
                    Path = try { $_.MainModule.FileName } catch { "Access Denied" }
                }
            }
        }
        
        # 의심스러운 프로세스 탐지
        $suspiciousProcesses = @()
        
        foreach ($process in $processes) {
            $suspicious = $false
            $reasons = @()
            
            try {
                # 시스템 프로세스인데 비정상적인 위치에서 실행
                if ($process.ProcessName -match "^(svchost|explorer|winlogon|csrss|lsass)$") {
                    $expectedPaths = @(
                        "$env:SystemRoot\System32",
                        "$env:SystemRoot\SysWOW64"
                    )
                    
                    $processPath = $process.MainModule.FileName
                    $isValidPath = $false
                    foreach ($path in $expectedPaths) {
                        if ($processPath -like "$path\*") {
                            $isValidPath = $true
                            break
                        }
                    }
                    
                    if (-not $isValidPath) {
                        $suspicious = $true
                        $reasons += "시스템 프로세스가 비정상적인 위치에서 실행"
                    }
                }
                
                # 서명되지 않은 실행 파일
                if ($process.MainModule.FileName) {
                    $signature = Get-AuthenticodeSignature $process.MainModule.FileName -ErrorAction SilentlyContinue
                    if ($signature -and $signature.Status -ne "Valid") {
                        $suspicious = $true
                        $reasons += "디지털 서명이 유효하지 않음"
                    }
                }
                
                # 높은 네트워크 활동
                $connections = Get-NetTCPConnection -OwningProcess $process.Id -ErrorAction SilentlyContinue
                if ($connections -and $connections.Count -gt 10) {
                    $suspicious = $true
                    $reasons += "과도한 네트워크 연결 ($($connections.Count)개)"
                }
                
            } catch {
                # 접근 권한 문제 등으로 인한 오류는 무시
            }
            
            if ($suspicious) {
                $suspiciousProcesses += @{
                    Name = $process.ProcessName
                    PID = $process.Id
                    Path = try { $process.MainModule.FileName } catch { "Access Denied" }
                    StartTime = $process.StartTime
                    Reasons = $reasons
                }
            }
        }
        
        $analysis.SuspiciousProcesses = $suspiciousProcesses
        
        # 서비스 분석
        $services = Get-Service
        $analysis.ServicesSummary = @{
            TotalServices = $services.Count
            RunningServices = ($services | Where-Object {$_.Status -eq "Running"}).Count
            StoppedServices = ($services | Where-Object {$_.Status -eq "Stopped"}).Count
        }
        
        # 최근 생성된 서비스 찾기
        $recentServices = @()
        $serviceKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
            $serviceName = $_.PSChildName
            $lastWriteTime = $_.LastWriteTime
            
            if ($lastWriteTime -gt (Get-Date).AddDays(-$TimeRange)) {
                $service = Get-Service $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $recentServices += @{
                        Name = $serviceName
                        DisplayName = $service.DisplayName
                        Status = $service.Status
                        CreatedDate = $lastWriteTime
                    }
                }
            }
        }
        
        $analysis.RecentServices = $recentServices
        
        Write-Log "프로세스 분석 완료 - 의심스러운 프로세스 $($suspiciousProcesses.Count)개 발견"
        return $analysis
        
    } catch {
        Write-Log "프로세스 분석 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "ProcessAnalysis: $($_.Exception.Message)"
        return $null
    }
}

# 네트워크 분석 모듈
function Get-NetworkAnalysis {
    Write-Log "네트워크 분석 시작"
    
    $analysis = @{}
    
    try {
        # TCP 연결 분석
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $tcpConnections = Get-NetTCPConnection
        } else {
            # PowerShell 2.0 호환 방식
            $netstatOutput = netstat -ano
            $tcpConnections = @()
            # netstat 출력 파싱 코드 생략 (복잡함)
        }
        
        $analysis.NetworkConnections = @{
            TotalTCPConnections = $tcpConnections.Count
            EstablishedConnections = ($tcpConnections | Where-Object {$_.State -eq "Established"}).Count
            ListeningPorts = ($tcpConnections | Where-Object {$_.State -eq "Listen"}).Count
        }
        
        # 의심스러운 연결 탐지
        $suspiciousConnections = @()
        
        foreach ($conn in ($tcpConnections | Where-Object {$_.State -eq "Established"})) {
            $suspicious = $false
            $reasons = @()
            
            # 비표준 포트 체크
            if ($conn.RemotePort -in @(6667, 6668, 6669, 7000, 8080, 4444, 5555, 31337)) {
                $suspicious = $true
                $reasons += "알려진 백도어/봇넷 포트"
            }
            
            # 외부 IP 연결 (사설 IP 제외)
            if ($conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)" -and 
                $conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "::") {
                
                # 프로세스 정보 가져오기
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($process -and $process.ProcessName -notin @("chrome", "firefox", "iexplore", "outlook", "teams")) {
                    $suspicious = $true
                    $reasons += "알려지지 않은 프로세스의 외부 연결"
                }
            }
            
            if ($suspicious) {
                $processName = try { (Get-Process -Id $conn.OwningProcess).ProcessName } catch { "Unknown" }
                $suspiciousConnections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    ProcessName = $processName
                    PID = $conn.OwningProcess
                    Reasons = $reasons
                }
            }
        }
        
        $analysis.SuspiciousConnections = $suspiciousConnections
        
        # 리스닝 포트 분석
        $listeningPorts = $tcpConnections | Where-Object {$_.State -eq "Listen"} | ForEach-Object {
            $processName = try { (Get-Process -Id $_.OwningProcess).ProcessName } catch { "Unknown" }
            @{
                Port = $_.LocalPort
                Address = $_.LocalAddress
                ProcessName = $processName
                PID = $_.OwningProcess
            }
        } | Sort-Object Port
        
        $analysis.ListeningPorts = $listeningPorts
        
        Write-Log "네트워크 분석 완료 - 의심스러운 연결 $($suspiciousConnections.Count)개 발견"
        return $analysis
        
    } catch {
        Write-Log "네트워크 분석 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "NetworkAnalysis: $($_.Exception.Message)"
        return $null
    }
}

# 자동 시작 프로그램 분석 모듈
function Get-AutostartAnalysis {
    Write-Log "자동 시작 프로그램 분석 시작"
    
    $analysis = @{}
    $autostartItems = @()
    
    try {
        # 레지스트리 기반 자동 시작 항목들
        $runKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($keyPath in $runKeys) {
            try {
                $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                if ($items) {
                    $items.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                        $autostartItems += @{
                            Location = $keyPath
                            Name = $_.Name
                            Command = $_.Value
                            Type = "Registry"
                        }
                    }
                }
            } catch {
                # 키가 존재하지 않을 수 있음
            }
        }
        
        # 서비스 자동 시작
        $autoServices = Get-Service | Where-Object {$_.StartType -eq "Automatic"}
        foreach ($service in $autoServices) {
            $servicePath = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'").PathName
            $autostartItems += @{
                Location = "Services"
                Name = $service.Name
                Command = $servicePath
                Type = "Service"
                Status = $service.Status
            }
        }
        
        # 시작 폴더
        $startupFolders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                Get-ChildItem $folder | ForEach-Object {
                    $autostartItems += @{
                        Location = $folder
                        Name = $_.Name
                        Command = $_.FullName
                        Type = "StartupFolder"
                    }
                }
            }
        }
        
        # 스케줄된 작업
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $scheduledTasks = Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
            foreach ($task in $scheduledTasks) {
                $autostartItems += @{
                    Location = "TaskScheduler"
                    Name = $task.TaskName
                    Command = $task.Actions.Execute
                    Type = "ScheduledTask"
                    State = $task.State
                }
            }
        }
        
        $analysis.AutostartItems = $autostartItems
        $analysis.Summary = @{
            TotalItems = $autostartItems.Count
            RegistryItems = ($autostartItems | Where-Object {$_.Type -eq "Registry"}).Count
            Services = ($autostartItems | Where-Object {$_.Type -eq "Service"}).Count
            StartupFolderItems = ($autostartItems | Where-Object {$_.Type -eq "StartupFolder"}).Count
            ScheduledTasks = ($autostartItems | Where-Object {$_.Type -eq "ScheduledTask"}).Count
        }
        
        Write-Log "자동 시작 프로그램 분석 완료 - 총 $($autostartItems.Count)개 항목 발견"
        return $analysis
        
    } catch {
        Write-Log "자동 시작 프로그램 분석 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "AutostartAnalysis: $($_.Exception.Message)"
        return $null
    }
}

# 이벤트 로그 분석 모듈
function Get-EventLogAnalysis {
    param([int]$Days = 7)
    
    Write-Log "이벤트 로그 분석 시작 (최근 $Days일)"
    
    $analysis = @{}
    $startDate = (Get-Date).AddDays(-$Days)
    
    try {
        # 보안 로그 분석
        $securityEvents = @()
        
        # 로그온 실패 (이벤트 ID 4625)
        if (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue) {
            $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$startDate} -ErrorAction SilentlyContinue
            if ($failedLogons) {
                $securityEvents += @{
                    Type = "Failed Logons"
                    Count = $failedLogons.Count
                    Events = $failedLogons | Select-Object -First 10 | ForEach-Object {
                        @{
                            TimeCreated = $_.TimeCreated
                            ID = $_.Id
                            Message = $_.Message
                        }
                    }
                }
            }
            
            # 성공한 로그온 (이벤트 ID 4624)
            $successLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startDate} -ErrorAction SilentlyContinue
            if ($successLogons) {
                $securityEvents += @{
                    Type = "Successful Logons"
                    Count = $successLogons.Count
                    RecentEvents = $successLogons | Select-Object -First 5 | ForEach-Object {
                        @{
                            TimeCreated = $_.TimeCreated
                            ID = $_.Id
                        }
                    }
                }
            }
        }
        
        $analysis.SecurityEvents = $securityEvents
        
        # 시스템 로그 분석
        $systemEvents = @()
        
        # 시스템 오류 및 경고
        $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=$startDate} -ErrorAction SilentlyContinue
        if ($systemErrors) {
            $systemEvents += @{
                Type = "System Errors and Warnings"
                Count = $systemErrors.Count
                TopEvents = $systemErrors | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                    @{
                        EventID = $_.Name
                        Count = $_.Count
                        Sample = $_.Group.LevelDisplayName + ": " + $_.Group.Message.Substring(0, [Math]::Min(100, $_.Group.Message.Length))
                    }
                }
            }
        }
        
        $analysis.SystemEvents = $systemEvents
        
        # PowerShell 로그 분석 (가능한 경우)
        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$startDate} -ErrorAction SilentlyContinue
        if ($psEvents) {
            $analysis.PowerShellEvents = @{
                TotalEvents = $psEvents.Count
                RecentCommands = $psEvents | Where-Object {$_.Id -eq 4104} | Select-Object -First 10 | ForEach-Object {
                    @{
                        TimeCreated = $_.TimeCreated
                        ScriptBlock = $_.Properties.Value
                    }
                }
            }
        }
        
        Write-Log "이벤트 로그 분석 완료"
        return $analysis
        
    } catch {
        Write-Log "이벤트 로그 분석 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "EventLogAnalysis: $($_.Exception.Message)"
        return $null
    }
}

# 파일 시스템 분석 모듈
function Get-FileSystemAnalysis {
    param([int]$Days = 7)
    
    Write-Log "파일 시스템 분석 시작 (최근 $Days일)"
    
    $analysis = @{}
    $startDate = (Get-Date).AddDays(-$Days)
    
    try {
        # 최근 생성된 실행 파일
        $recentExecutables = @()
        $searchPaths = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64", 
            "$env:TEMP",
            "$env:APPDATA",
            "$env:LOCALAPPDATA"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                Get-ChildItem $path -Recurse -Include "*.exe","*.dll","*.scr","*.com" -ErrorAction SilentlyContinue | 
                Where-Object {$_.CreationTime -gt $startDate -or $_.LastWriteTime -gt $startDate} |
                ForEach-Object {
                    $recentExecutables += @{
                        Path = $_.FullName
                        Name = $_.Name
                        CreationTime = $_.CreationTime
                        LastWriteTime = $_.LastWriteTime
                        Size = $_.Length
                        Directory = $_.DirectoryName
                    }
                }
            }
        }
        
        $analysis.RecentExecutables = $recentExecutables | Sort-Object CreationTime -Descending
        
        # 의심스러운 파일 확장자
        $suspiciousExtensions = @("*.vbs", "*.bat", "*.cmd", "*.ps1", "*.jar", "*.scr")
        $suspiciousFiles = @()
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                foreach ($ext in $suspiciousExtensions) {
                    Get-ChildItem $path -Recurse -Include $ext -ErrorAction SilentlyContinue |
                    Where-Object {$_.CreationTime -gt $startDate} |
                    ForEach-Object {
                        $suspiciousFiles += @{
                            Path = $_.FullName
                            Extension = $_.Extension
                            CreationTime = $_.CreationTime
                            Size = $_.Length
                        }
                    }
                }
            }
        }
        
        $analysis.SuspiciousFiles = $suspiciousFiles
        
        # 임시 디렉터리 분석
        $tempDirs = @($env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp")
        $tempAnalysis = @()
        
        foreach ($tempDir in $tempDirs) {
            if (Test-Path $tempDir) {
                $tempFiles = Get-ChildItem $tempDir -ErrorAction SilentlyContinue
                $tempAnalysis += @{
                    Path = $tempDir
                    FileCount = $tempFiles.Count
                    TotalSize = ($tempFiles | Measure-Object Length -Sum).Sum
                    RecentFiles = $tempFiles | Where-Object {$_.CreationTime -gt $startDate} | 
                                 Select-Object -First 10 | ForEach-Object {
                        @{
                            Name = $_.Name
                            CreationTime = $_.CreationTime
                            Size = $_.Length
                        }
                    }
                }
            }
        }
        
        $analysis.TempDirectories = $tempAnalysis
        
        Write-Log "파일 시스템 분석 완료 - 최근 실행 파일 $($recentExecutables.Count)개, 의심스러운 파일 $($suspiciousFiles.Count)개 발견"
        return $analysis
        
    } catch {
        Write-Log "파일 시스템 분석 중 오류: $($_.Exception.Message)" "ERROR"
        $script:Errors += "FileSystemAnalysis: $($_.Exception.Message)"
        return $null
    }
}

# 메인 분석 함수
function Start-IncidentAnalysis {
    param(
        [string]$Scope,
        [int]$TimeRange
    )
    
    Write-Log "침해사고 분석 시작 - 범위: $Scope, 기간: $TimeRange일"
    
    $results = @{}
    
    # 기본 정보는 항상 수집
    $results.SystemInfo = Get-SystemBasicInfo
    $results.ProcessAnalysis = Get-ProcessAnalysis
    $results.NetworkAnalysis = Get-NetworkAnalysis
    
    if ($Scope -in @("Standard", "Deep")) {
        $results.AutostartAnalysis = Get-AutostartAnalysis
        $results.EventLogAnalysis = Get-EventLogAnalysis -Days $TimeRange
        $results.FileSystemAnalysis = Get-FileSystemAnalysis -Days $TimeRange
    }
    
    if ($Scope -eq "Deep") {
        # 추가 심화 분석 (미래 확장용)
        Write-Log "심화 분석 기능은 향후 버전에서 제공될 예정입니다."
    }
    
    $results.AnalysisMetadata = @{
        StartTime = $script:StartTime
        EndTime = Get-Date
        Duration = (Get-Date) - $script:StartTime
        Scope = $Scope
        TimeRange = $TimeRange
        Errors = $script:Errors
    }
    
    return $results
}

# 보고서 생성 함수
function Generate-Report {
    param($Results, $OutputPath)
    
    Write-Log "분석 보고서 생성 중..."
    
    # JSON 형식으로 상세 결과 저장
    $Results | ConvertTo-Json -Depth 10 | Out-File "$OutputPath\analysis_results.json" -Encoding UTF8
    
    # HTML 보고서 생성
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows 침해사고 분석 보고서</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; }
        .warning { background-color: #f39c12; color: white; padding: 10px; margin: 10px 0; }
        .error { background-color: #e74c3c; color: white; padding: 10px; margin: 10px 0; }
        .info { background-color: #3498db; color: white; padding: 10px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .suspicious { background-color: #ffebee; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows 침해사고 분석 보고서</h1>
        <p>생성일시: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>분석 범위: $($Results.AnalysisMetadata.Scope)</p>
        <p>분석 기간: $($Results.AnalysisMetadata.TimeRange)일</p>
    </div>
"@

    # 시스템 정보 섹션
    if ($Results.SystemInfo) {
        $html += @"
    <div class="section">
        <h2>시스템 기본 정보</h2>
        <table>
            <tr><th>운영체제</th><td>$($Results.SystemInfo.OS.ProductName)</td></tr>
            <tr><th>버전</th><td>$($Results.SystemInfo.OS.Version)</td></tr>
            <tr><th>아키텍처</th><td>$($Results.SystemInfo.OS.Architecture)</td></tr>
            <tr><th>마지막 재부팅</th><td>$($Results.SystemInfo.OS.LastBootUpTime)</td></tr>
            <tr><th>총 메모리</th><td>$($Results.SystemInfo.OS.TotalPhysicalMemory) GB</td></tr>
            <tr><th>보안 패치 수</th><td>$($Results.SystemInfo.SecurityPatches.TotalCount)</td></tr>
            <tr><th>마지막 패치</th><td>$($Results.SystemInfo.SecurityPatches.LastPatchDate)</td></tr>
        </table>
    </div>
"@
    }

    # 프로세스 분석 섹션
    if ($Results.ProcessAnalysis) {
        $html += @"
    <div class="section">
        <h2>프로세스 분석</h2>
        <p>총 프로세스 수: $($Results.ProcessAnalysis.ProcessSummary.TotalProcesses)</p>
"@
        
        if ($Results.ProcessAnalysis.SuspiciousProcesses.Count -gt 0) {
            $html += '<div class="warning">의심스러운 프로세스가 발견되었습니다!</div>'
            $html += '<table><tr><th>프로세스명</th><th>PID</th><th>경로</th><th>의심 이유</th></tr>'
            
            foreach ($proc in $Results.ProcessAnalysis.SuspiciousProcesses) {
                $reasons = $proc.Reasons -join ", "
                $html += "<tr class='suspicious'><td>$($proc.Name)</td><td>$($proc.PID)</td><td>$($proc.Path)</td><td>$reasons</td></tr>"
            }
            $html += '</table>'
        } else {
            $html += '<div class="info">의심스러운 프로세스가 발견되지 않았습니다.</div>'
        }
        
        $html += '</div>'
    }

    # 네트워크 분석 섹션
    if ($Results.NetworkAnalysis) {
        $html += @"
    <div class="section">
        <h2>네트워크 분석</h2>
        <p>총 TCP 연결: $($Results.NetworkAnalysis.NetworkConnections.TotalTCPConnections)</p>
        <p>설정된 연결: $($Results.NetworkAnalysis.NetworkConnections.EstablishedConnections)</p>
        <p>리스닝 포트: $($Results.NetworkAnalysis.NetworkConnections.ListeningPorts)</p>
"@
        
        if ($Results.NetworkAnalysis.SuspiciousConnections.Count -gt 0) {
            $html += '<div class="warning">의심스러운 네트워크 연결이 발견되었습니다!</div>'
            $html += '<table><tr><th>로컬</th><th>원격</th><th>프로세스</th><th>의심 이유</th></tr>'
            
            foreach ($conn in $Results.NetworkAnalysis.SuspiciousConnections) {
                $reasons = $conn.Reasons -join ", "
                $html += "<tr class='suspicious'><td>$($conn.LocalAddress):$($conn.LocalPort)</td><td>$($conn.RemoteAddress):$($conn.RemotePort)</td><td>$($conn.ProcessName)</td><td>$reasons</td></tr>"
            }
            $html += '</table>'
        } else {
            $html += '<div class="info">의심스러운 네트워크 연결이 발견되지 않았습니다.</div>'
        }
        
        $html += '</div>'
    }

    # 오류 정보
    if ($Results.AnalysisMetadata.Errors.Count -gt 0) {
        $html += '<div class="section"><h2>분석 중 발생한 오류</h2>'
        foreach ($error in $Results.AnalysisMetadata.Errors) {
            $html += "<div class='error'>$error</div>"
        }
        $html += '</div>'
    }

    $html += @"
    <div class="section">
        <h2>분석 정보</h2>
        <p>분석 시작: $($Results.AnalysisMetadata.StartTime)</p>
        <p>분석 종료: $($Results.AnalysisMetadata.EndTime)</p>
        <p>소요 시간: $($Results.AnalysisMetadata.Duration.ToString("hh\:mm\:ss"))</p>
    </div>
</body>
</html>
"@

    $html | Out-File "$OutputPath\analysis_report.html" -Encoding UTF8
    
    Write-Log "보고서 생성 완료: $OutputPath\analysis_report.html"
}

# 메인 실행 부분
try {
    # 출력 디렉터리 생성
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Log "Windows 침해사고 분석 스크립트 시작"
    Write-Log "PowerShell 버전: $($PSVersionTable.PSVersion)"
    Write-Log "관리자 권한: $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))"
    
    # 메인 분석 실행
    $script:Results = Start-IncidentAnalysis -Scope $AnalysisScope -TimeRange $TimeRange
    
    # 결과 저장
    if ($GenerateReport) {
        Generate-Report -Results $script:Results -OutputPath $OutputPath
    }
    
    # 간단한 요약 출력
    Write-Host "`n=== 분석 요약 ===" -ForegroundColor Green
    
    if ($script:Results.ProcessAnalysis -and $script:Results.ProcessAnalysis.SuspiciousProcesses.Count -gt 0) {
        Write-Host "⚠️  의심스러운 프로세스: $($script:Results.ProcessAnalysis.SuspiciousProcesses.Count)개" -ForegroundColor Yellow
    }
    
    if ($script:Results.NetworkAnalysis -and $script:Results.NetworkAnalysis.SuspiciousConnections.Count -gt 0) {
        Write-Host "⚠️  의심스러운 네트워크 연결: $($script:Results.NetworkAnalysis.SuspiciousConnections.Count)개" -ForegroundColor Yellow
    }
    
    if ($script:Errors.Count -gt 0) {
        Write-Host "❌ 분석 중 오류: $($script:Errors.Count)개" -ForegroundColor Red
    }
    
    Write-Host "✅ 분석 완료. 결과는 '$OutputPath' 디렉터리에 저장되었습니다." -ForegroundColor Green
    
} catch {
    Write-Log "스크립트 실행 중 치명적 오류: $($_.Exception.Message)" "ERROR"
    Write-Host "스크립트 실행 실패: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
