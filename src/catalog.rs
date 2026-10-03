//! The collection plan. Each collector is a named list of probes; the order of this table
//! IS the order of collection, most volatile first (RFC 3227).
//!
//! PowerShell bodies must not contain double quotes (they travel as one command-line
//! argument) or line comments (they are collapsed to one line). A test enforces this.
use crate::native;
use crate::probe::Probe::{self, *};

pub struct Collector {
    pub name: &'static str,
    pub phase: &'static str,
    /// MITRE ATT&CK techniques this evidence helps investigate.
    pub mitre: &'static str,
    /// Changes system state (driver load, trace session). Runs only with `--live`.
    pub live: bool,
    pub probes: &'static [Probe],
}

const fn c(name: &'static str, phase: &'static str, mitre: &'static str, probes: &'static [Probe]) -> Collector {
    Collector {
        name,
        phase,
        mitre,
        live: false,
        probes,
    }
}

const fn live(name: &'static str, phase: &'static str, mitre: &'static str, probes: &'static [Probe]) -> Collector {
    Collector {
        name,
        phase,
        mitre,
        live: true,
        probes,
    }
}

const ANY: &[&str] = &[];
const EXECUTABLES: &[&str] = &[
    "*.exe", "*.dll", "*.sys", "*.scr", "*.com", "*.pif", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.vbe", "*.js", "*.jse", "*.wsf", "*.hta",
    "*.msi", "*.lnk", "*.iso", "*.img",
];

pub static CATALOG: &[Collector] = &[
    // ---------------------------------------------------------------- most volatile: memory
    live("RAM_Dump", "Memory", "T1003 T1055 T1620", &[Native("Capture", native::ram_dump)]),
    c("Pagefile", "Memory", "T1003", &[
        Reg("Configuration", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Power",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
        ], 0),
        Ps("Usage", "Get-CimInstance Win32_PageFileUsage|Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage"),
        Files("CrashDumps", &[r"%SystemRoot%\MEMORY.DMP", r"%SystemRoot%\Minidump", r"%SystemRoot%\LiveKernelReports"], &["*.dmp"], 2, false),
    ]),
    c("Named_Pipes", "Memory", "T1071 T1570 T1021.002", &[Native("Pipes", native::named_pipes)]),
    c("Processes", "Execution", "T1055 T1036 T1059", &[
        Ps("Processes", "$n=@{};$c=@{};$p=@(Get-CimInstance Win32_Process);
            $p|ForEach-Object{$n[[int]$_.ProcessId]=$_.Name};
            $p|ForEach-Object{$f=$_.ExecutablePath;
              if($f -and -not $c.ContainsKey($f)){$c[$f]=@([string](Get-AuthenticodeSignature -LiteralPath $f).Status,(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash)};
              $o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner;
              [pscustomobject]@{Name=$_.Name;PID=$_.ProcessId;PPID=$_.ParentProcessId;Parent=$n[[int]$_.ParentProcessId];
                CommandLine=$_.CommandLine;Path=$f;SHA256=$(if($f){$c[$f][1]});Signature=$(if($f){$c[$f][0]});
                Owner=($o.Domain,$o.User -join '\\').Trim('\\');Session=$_.SessionId;Started=T $_.CreationDate;
                WorkingSetMB=[math]::Round($_.WorkingSetSize/1MB,1);Threads=$_.ThreadCount;Handles=$_.HandleCount}}"),
        Cmd("TaskList", "tasklist.exe", &["/v", "/fo", "csv"]),
        Cmd("TaskListServices", "tasklist.exe", &["/svc", "/fo", "csv"]),
    ]),
    c("Loaded_Modules", "Execution", "T1055.001 T1574.001 T1574.002", &[
        Ps("NonSystemModules", "$c=@{};Get-Process|ForEach-Object{$pn=$_.ProcessName;$id=$_.Id;
            $_.Modules|Where-Object{$_.FileName -notmatch '(?i)\\\\Windows\\\\(System32|SysWOW64|WinSxS|Microsoft\\.NET|assembly|SystemApps)\\\\'}|
            ForEach-Object{$f=$_.FileName;
              if(-not $c.ContainsKey($f)){$c[$f]=@([string](Get-AuthenticodeSignature -LiteralPath $f).Status,(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash)};
              [pscustomobject]@{Process=$pn;PID=$id;Module=$_.ModuleName;Path=$f;Base=('0x{0:X}' -f [int64]$_.BaseAddress);
                Size=$_.ModuleMemorySize;SHA256=$c[$f][1];Signature=$c[$f][0]}}}"),
    ]),
    // ---------------------------------------------------------------- volatile network state
    c("Network_State", "Network", "T1071 T1049 T1557 T1568", &[
        Ps("TcpConnections", "$m=@{};Get-Process|ForEach-Object{$m[$_.Id]=$_.ProcessName};
            Get-NetTCPConnection|ForEach-Object{[pscustomobject]@{Local=$_.LocalAddress;LocalPort=$_.LocalPort;Remote=$_.RemoteAddress;
              RemotePort=$_.RemotePort;State=[string]$_.State;PID=$_.OwningProcess;Process=$m[[int]$_.OwningProcess];Created=T $_.CreationTime}}"),
        Ps("UdpEndpoints", "$m=@{};Get-Process|ForEach-Object{$m[$_.Id]=$_.ProcessName};
            Get-NetUDPEndpoint|ForEach-Object{[pscustomobject]@{Local=$_.LocalAddress;LocalPort=$_.LocalPort;PID=$_.OwningProcess;
              Process=$m[[int]$_.OwningProcess];Created=T $_.CreationTime}}"),
        Ps("DnsCache", "Get-DnsClientCache|Select-Object Entry,Name,Type,Status,TimeToLive,Data"),
        Cmd("Netstat", "netstat.exe", &["-ano"]),
        Cmd("Arp", "arp.exe", &["-a"]),
        Cmd("IpConfig", "ipconfig.exe", &["/all"]),
        Cmd("DnsCacheRaw", "ipconfig.exe", &["/displaydns"]),
        Cmd("Routes", "route.exe", &["print"]),
        Cmd("NetBiosSessions", "nbtstat.exe", &["-S"]),
        Text("Hosts", &[r"%SystemRoot%\System32\drivers\etc\hosts", r"%SystemRoot%\System32\drivers\etc\lmhosts"], ANY, 0),
    ]),
    c("Sessions", "Network", "T1021 T1078 T1550 T1558", &[
        Cmd("LoggedOnUsers", "quser.exe", &[]),
        Cmd("TerminalSessions", "qwinsta.exe", &[]),
        Ps("SmbSessions", "Get-SmbSession|Select-Object SessionId,ClientComputerName,ClientUserName,NumOpens,SecondsExists,SecondsIdle,Dialect"),
        Ps("SmbOpenFiles", "Get-SmbOpenFile|Select-Object FileId,SessionId,ClientComputerName,ClientUserName,Path"),
        Ps("SmbShares", "Get-SmbShare|Select-Object Name,Path,Description,ShareType,CurrentUsers,Special"),
        Ps("SmbMappings", "Get-SmbMapping|Select-Object LocalPath,RemotePath,Status"),
        Cmd("NetUse", "net.exe", &["use"]),
        Cmd("KerberosTickets", "klist.exe", &[]),
        Cmd("KerberosSessions", "klist.exe", &["sessions"]),
        Cmd("StoredCredentials", "cmdkey.exe", &["/list"]),
    ]),
    c("Network_Config", "Network", "T1090 T1021.001 T1016", &[
        Cmd("WinHttpProxy", "netsh.exe", &["winhttp", "show", "proxy"]),
        // Profile names only: stored Wi-Fi keys are never requested (no key=clear).
        Cmd("WifiProfiles", "netsh.exe", &["wlan", "show", "profiles"]),
        Cmd("PortProxy", "netsh.exe", &["interface", "portproxy", "show", "all"]),
        Reg("Proxy", &[
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        ], 0),
        Reg("RdpClientHistory", &[r"HKCU\Software\Microsoft\Terminal Server Client"], 2),
        Reg("RdpServer", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        ], 0),
        Reg("NetworkProfiles", &[r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"], 1),
        Reg("TcpipParameters", &[r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"], 0),
        Reg("WinRM", &[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM"], 2),
        Reg("MappedDriveHistory", &[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU", r"HKCU\Network"], 1),
        Files("RdpBitmapCache", &[r"{users}\AppData\Local\Microsoft\Terminal Server Client\Cache"], ANY, 1, false),
        Files("ClipboardHistory", &[r"{users}\AppData\Local\Microsoft\Windows\Clipboard"], ANY, 4, false),
    ]),
    // ---------------------------------------------------------------- system baseline
    c("System_Info", "System", "T1082 T1124", &[
        Ps("System", "$o=Get-CimInstance Win32_OperatingSystem;$s=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS;
            $p=Get-CimInstance Win32_Processor|Select-Object -First 1;
            [pscustomobject]@{Hostname=$env:COMPUTERNAME;OS=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;Architecture=$o.OSArchitecture;
              ProductType=$o.ProductType;Installed=T $o.InstallDate;LastBoot=T $o.LastBootUpTime;LocalTime=(Get-Date).ToString('o');
              TimeZone=[TimeZoneInfo]::Local.Id;Manufacturer=$s.Manufacturer;Model=$s.Model;Domain=$s.Domain;DomainRole=$s.DomainRole;
              PartOfDomain=$s.PartOfDomain;RAMGB=[math]::Round($s.TotalPhysicalMemory/1GB,2);Serial=$b.SerialNumber;
              BIOS=$b.SMBIOSBIOSVersion;CPU=$p.Name;Cores=$p.NumberOfCores;PowerShell=[string]$PSVersionTable.PSVersion}"),
        Ps("Hotfixes", "Get-HotFix|ForEach-Object{[pscustomobject]@{Id=$_.HotFixID;Description=$_.Description;InstalledOn=T $_.InstalledOn;InstalledBy=$_.InstalledBy}}"),
        Ps("Volumes", "Get-CimInstance Win32_LogicalDisk|Select-Object DeviceID,DriveType,FileSystem,VolumeName,VolumeSerialNumber,Size,FreeSpace"),
        Ps("NetworkAdapters", "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE'|
            Select-Object Description,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DHCPEnabled,DHCPServer,DNSDomain"),
        Cmd("TimeSync", "w32tm.exe", &["/query", "/status"]),
        Cmd("SystemInfo", "systeminfo.exe", &[]),
        Reg("MachineEnvironment", &[r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"], 0),
        Reg("WindowsVersion", &[r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"], 0),
        Reg("WindowsUpdate", &[
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
        ], 2),
    ]),
    // ---------------------------------------------------------------- event logs
    c("EventLog_Security", "EventLogs", "T1078 T1136 T1098 T1059 T1053", &[
        Ps("Logon", "Ev 'Security' @(4624,4625,4634,4647,4648,4672,4778,4779) 4000"),
        Ps("AccountManagement", "Ev 'Security' @(4720,4722,4723,4724,4725,4726,4728,4732,4738,4740,4756,4767,4742) 2000"),
        Ps("ProcessCreation", "Ev 'Security' @(4688,4689) 4000 1200"),
        Ps("PolicyAndTasks", "Ev 'Security' @(4698,4699,4700,4701,4702,4719,4946,4947,4950,1102) 2000 1500"),
        Ps("KerberosNtlm", "Ev 'Security' @(4768,4769,4771,4776) 4000"),
        Ps("ObjectAccess", "Ev 'Security' @(4662,4663,4670,4656,5140,5145) 3000"),
        Cmd("AuditPolicy", "auditpol.exe", &["/get", "/category:*"]),
    ]),
    c("EventLog_System", "EventLogs", "T1543.003 T1569.002 T1021.001 T1197 T1047", &[
        Ps("System", "Ev 'System' @(7045,7036,7040,7034,6005,6006,6008,1074,41,104) 3000"),
        Ps("ApplicationCrashes", "Ev 'Application' @(1000,1001,1002) 1000"),
        Ps("TaskScheduler", "Ev 'Microsoft-Windows-TaskScheduler/Operational' @(106,140,141,200,201,325) 2000"),
        Ps("WmiActivity", "Ev 'Microsoft-Windows-WMI-Activity/Operational' @(5857,5858,5859,5860,5861) 1000 1500"),
        Ps("RdpLocalSessions", "Ev 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25) 2000"),
        Ps("RdpRemoteConnections", "Ev 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149) 2000"),
        Ps("Bits", "Ev 'Microsoft-Windows-Bits-Client/Operational' @(3,4,59,60,61) 1000"),
        Ps("WinRM", "Ev 'Microsoft-Windows-WinRM/Operational' @(6,8,15,16,33,91) 1000"),
        Ps("AppLocker", "Ev 'Microsoft-Windows-AppLocker/EXE and DLL' @(8003,8004,8006,8007) 1000"),
        Ps("Sysmon", "Ev 'Microsoft-Windows-Sysmon/Operational' @(1,3,7,8,10,11,12,13,22,25) 4000 1500"),
        Ps("VolumeShadowCopy", "Ev 'System' @(8193,8194,8197,8199) 500;Ev 'Application' @(8193,8194,8224,12289) 500"),
    ]),
    c("EventLog_PowerShell", "EventLogs", "T1059.001 T1027 T1562.002", &[
        Ps("ScriptBlocks", "Ev 'Microsoft-Windows-PowerShell/Operational' 4104 2000 8000"),
        Ps("ModuleLogging", "Ev 'Microsoft-Windows-PowerShell/Operational' 4103 1000 2000"),
        Ps("EngineLifecycle", "Ev 'Windows PowerShell' @(400,403,600,800) 1500 1500"),
        Reg("LoggingPolicy", &[r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell", r"HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell"], 2),
        Text("ConsoleHistory", &[r"{users}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"], &["*.txt"], 0),
        Text("Transcripts", &[r"{users}\Documents", r"{users}\Documents\WindowsPowerShell", r"%SystemDrive%\Transcripts", r"%SystemDrive%\PSTranscripts"],
            &["PowerShell_transcript*.txt"], 3),
    ]),
    c("EventLog_Raw", "EventLogs", "T1070.001", &[Native("Evtx", native::evtx_export)]),
    // ---------------------------------------------------------------- persistence
    c("Autoruns_Registry", "Persistence", "T1547.001 T1547.004 T1546.008 T1546.010 T1547.005 T1546.012", &[
        Reg("RunKeys", &[
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        ], 1),
        Reg("Winlogon", &[
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        ], 0),
        Reg("ImageFileExecutionOptions", &[
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
        ], 1),
        Reg("SessionManager", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        ], 0),
        Reg("LsaPackages", &[r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"], 0),
        Reg("ProvidersAndMonitors", &[
            r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors",
            r"HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
            r"HKLM\SOFTWARE\Microsoft\NetSh",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions",
        ], 1),
        Reg("ActiveSetup", &[r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components"], 1),
        Reg("GroupPolicyScripts", &[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts",
        ], 3),
        Reg("ComHijackCandidates", &[r"HKCU\Software\Classes\CLSID"], 2),
        Reg("ShellExtensions", &[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
        ], 1),
    ]),
    c("Scheduled_Tasks", "Persistence", "T1053.005", &[
        Ps("Tasks", "Get-ScheduledTask|ForEach-Object{$i=$_|Get-ScheduledTaskInfo;
            [pscustomobject]@{Path=$_.TaskPath;Name=$_.TaskName;State=[string]$_.State;Author=$_.Author;RunAs=$_.Principal.UserId;
              RunLevel=[string]$_.Principal.RunLevel;Actions=@($_.Actions|ForEach-Object{($_.Execute,$_.Arguments -join ' ').Trim()});
              Triggers=@($_.Triggers|ForEach-Object{$_.CimClass.CimClassName});Registered=$_.Date;LastRun=T $i.LastRunTime;
              NextRun=T $i.NextRunTime;LastResult=$i.LastTaskResult;Hidden=$_.Settings.Hidden}}"),
        Reg("TaskCache", &[r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"], 3),
        Files("TaskFiles", &[r"%SystemRoot%\System32\Tasks", r"%SystemRoot%\Tasks"], ANY, 6, true),
        Copy("TaskXml", &[r"%SystemRoot%\System32\Tasks", r"%SystemRoot%\Tasks"], ANY, 6),
    ]),
    c("Services", "Persistence", "T1543.003 T1569.002 T1014", &[
        Ps("Services", "Get-CimInstance Win32_Service|Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId,ServiceType,Description"),
        Ps("Drivers", "Get-CimInstance Win32_SystemDriver|Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType"),
        // Native view with per-service key last-write times (service install/change time).
        Reg("ServiceKeys", &[r"HKLM\SYSTEM\CurrentControlSet\Services"], 1),
    ]),
    c("Startup_Folders", "Persistence", "T1547.001 T1547.009", &[
        Files("Startup", &[
            r"{users}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
        ], ANY, 1, true),
        Copy("StartupItems", &[
            r"{users}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
        ], ANY, 1),
    ]),
    c("WMI_Persistence", "Persistence", "T1546.003", &[
        Ps("Subscriptions", "$ns='root\\subscription';[pscustomobject]@{
            Filters=@(Get-CimInstance -Namespace $ns -ClassName __EventFilter|Select-Object Name,Query,QueryLanguage,EventNamespace);
            CommandLineConsumers=@(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer|Select-Object Name,CommandLineTemplate,ExecutablePath,WorkingDirectory);
            ScriptConsumers=@(Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer|Select-Object Name,ScriptingEngine,ScriptFileName,ScriptText);
            Bindings=@(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding|ForEach-Object{[pscustomobject]@{Filter=[string]$_.Filter;Consumer=[string]$_.Consumer}})}"),
        Files("Repository", &[r"%SystemRoot%\System32\wbem\Repository"], ANY, 1, false),
    ]),
    // ---------------------------------------------------------------- defense evasion
    c("Firewall", "DefenseEvasion", "T1562.004", &[
        // Read natively from the policy store: every rule, without the slow firewall cmdlets.
        Reg("Policy", &[r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"], 2),
        Reg("GroupPolicy", &[r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"], 2),
        Cmd("Profiles", "netsh.exe", &["advfirewall", "show", "allprofiles"]),
    ]),
    c("Defender_AV", "DefenseEvasion", "T1562.001 T1089", &[
        Ps("Status", "Get-MpComputerStatus|Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,
            IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,AMProductVersion,
            AntivirusSignatureVersion,@{n='SignatureUpdated';e={T $_.AntivirusSignatureLastUpdated}},
            @{n='LastQuickScan';e={T $_.QuickScanEndTime}},@{n='LastFullScan';e={T $_.FullScanEndTime}}"),
        Ps("Preferences", "Get-MpPreference|Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress,
            DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,DisableBlockAtFirstSeen,
            MAPSReporting,SubmitSamplesConsent,EnableControlledFolderAccess,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions"),
        Ps("Detections", "Get-MpThreatDetection|ForEach-Object{[pscustomobject]@{ThreatID=$_.ThreatID;Name=(Get-MpThreat -ThreatID $_.ThreatID).ThreatName;
            Detected=T $_.InitialDetectionTime;Remediated=T $_.RemediationTime;Process=$_.ProcessName;User=$_.DomainUser;
            Resources=$_.Resources;ActionSuccess=$_.ActionSuccess}}"),
        Ps("RegisteredProducts", "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct|
            Select-Object displayName,productState,pathToSignedProductExe,timestamp"),
        Ps("Events", "Ev 'Microsoft-Windows-Windows Defender/Operational' @(1006,1007,1008,1009,1116,1117,1118,1119,5001,5004,5007,5010,5012) 2000 1500"),
        Reg("Policy", &[r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features"], 2),
        Reg("AmsiProviders", &[r"HKLM\SOFTWARE\Microsoft\AMSI\Providers"], 1),
        Files("Quarantine", &[r"%ProgramData%\Microsoft\Windows Defender\Quarantine"], ANY, 3, false),
        Copy("SupportLogs", &[r"%ProgramData%\Microsoft\Windows Defender\Support"], &["MPLog-*.log", "MPDetection-*.log"], 0),
    ]),
    c("Anti_Forensics", "DefenseEvasion", "T1070.001 T1562.002 T1070.004 T1490", &[
        Ps("LogCleared", "Ev 'Security' 1102 500 1500;Ev 'System' 104 500 1500"),
        Ps("AuditPolicyChanged", "Ev 'Security' 4719 500 1500"),
        Ps("LogChannels", "'Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-WMI-Activity/Operational'|
            ForEach-Object{$l=Get-WinEvent -ListLog $_;[pscustomobject]@{Log=$_;Enabled=$l.IsEnabled;Records=$l.RecordCount;
              MaxSizeBytes=$l.MaximumSizeInBytes;Mode=[string]$l.LogMode;LastWrite=T $l.LastWriteTime;Oldest=$l.OldestRecordNumber}}"),
        Cmd("UsnJournal", "fsutil.exe", &["usn", "queryjournal", "{drive}"]),
        Cmd("BootConfiguration", "bcdedit.exe", &["/enum", "all"]),
        Reg("Settings", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            r"HKLM\SYSTEM\CurrentControlSet\Control\FileSystem",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        ], 0),
    ]),
    // ---------------------------------------------------------------- accounts and credentials
    c("Local_Accounts", "Accounts", "T1136.001 T1098 T1078.003", &[
        Ps("Users", "Get-LocalUser|ForEach-Object{[pscustomobject]@{Name=$_.Name;SID=[string]$_.SID;Enabled=$_.Enabled;LastLogon=T $_.LastLogon;
            PasswordLastSet=T $_.PasswordLastSet;PasswordRequired=$_.PasswordRequired;PasswordExpires=T $_.PasswordExpires;
            Source=[string]$_.PrincipalSource;Description=$_.Description}}"),
        Ps("Groups", "Get-LocalGroup|ForEach-Object{$g=$_.Name;[pscustomobject]@{Group=$g;SID=[string]$_.SID;
            Members=@(Get-LocalGroupMember -Group $g|ForEach-Object{[pscustomobject]@{Name=$_.Name;SID=[string]$_.SID;Class=$_.ObjectClass;Source=[string]$_.PrincipalSource}})}}"),
        Cmd("NetUsers", "net.exe", &["user"]),
        Cmd("NetAdministrators", "net.exe", &["localgroup", "Administrators"]),
        Cmd("NetAccounts", "net.exe", &["accounts"]),
        Reg("ProfileList", &[r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"], 1),
    ]),
    c("Logon_Sessions", "Accounts", "T1078 T1110 T1021 T1550.002", &[
        Ps("Logons", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$since} -MaxEvents 8000|
            Where-Object{$_.Properties[8].Value -ne 5}|ForEach-Object{$p=$_.Properties;[pscustomobject]@{Time=T $_.TimeCreated;User=$p[5].Value;
              Domain=$p[6].Value;LogonId=('0x{0:x}' -f $p[7].Value);Type=$p[8].Value;Process=([string]$p[9].Value).Trim();
              AuthPackage=[string]$p[10].Value;Workstation=$p[11].Value;SourceIP=$p[18].Value;SourcePort=$p[19].Value}}"),
        Ps("FailedLogons", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -MaxEvents 8000|
            ForEach-Object{$p=$_.Properties;[pscustomobject]@{Time=T $_.TimeCreated;User=$p[5].Value;Domain=$p[6].Value;
              Status=('0x{0:x}' -f $p[7].Value);SubStatus=('0x{0:x}' -f $p[9].Value);Type=$p[10].Value;Workstation=$p[13].Value;SourceIP=$p[19].Value}}"),
        Ps("LogonSessions", "Get-CimInstance Win32_LogonSession|ForEach-Object{[pscustomobject]@{LogonId=$_.LogonId;Type=$_.LogonType;
            AuthPackage=$_.AuthenticationPackage;Started=T $_.StartTime}}"),
    ]),
    c("Credentials", "Credentials", "T1003 T1552 T1555", &[
        Reg("LsaConfiguration", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        ], 0),
        Reg("DeviceGuard", &[r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"], 2),
        // Key names and last-write times only - secret and cached-credential data is never read.
        RegNames("LsaSecretNames", &[r"HKLM\SECURITY\Policy\Secrets", r"HKLM\SECURITY\Cache"]),
        Files("DpapiMasterKeys", &[r"{users}\AppData\Roaming\Microsoft\Protect"], ANY, 2, false),
        Files("CredentialFiles", &[
            r"{users}\AppData\Roaming\Microsoft\Credentials",
            r"{users}\AppData\Local\Microsoft\Credentials",
            r"{users}\AppData\Local\Microsoft\Vault",
            r"%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Credentials",
        ], ANY, 2, false),
        Files("SshKeys", &[r"{users}\.ssh"], ANY, 1, false),
    ]),
    c("Certificates", "Credentials", "T1553.004 T1649", &[
        Ps("Stores", "'LocalMachine\\Root','LocalMachine\\CA','LocalMachine\\My','LocalMachine\\TrustedPublisher','LocalMachine\\Disallowed',
            'CurrentUser\\Root','CurrentUser\\My'|ForEach-Object{$s=$_;Get-ChildItem ('Cert:\\'+$s)|ForEach-Object{
              [pscustomobject]@{Store=$s;Subject=$_.Subject;Issuer=$_.Issuer;Thumbprint=$_.Thumbprint;Serial=$_.SerialNumber;
                NotBefore=T $_.NotBefore;NotAfter=T $_.NotAfter;HasPrivateKey=$_.HasPrivateKey;SelfSigned=($_.Subject -eq $_.Issuer);
                Algorithm=$_.SignatureAlgorithm.FriendlyName}}}"),
        // Thumbprints with key last-write time = when each root was installed.
        RegNames("RootStoreKeys", &[
            r"HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates",
            r"HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates",
            r"HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates",
            r"HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates",
            r"HKCU\Software\Microsoft\SystemCertificates\Root\Certificates",
        ]),
    ]),
    // ---------------------------------------------------------------- registry execution evidence
    c("Execution_Artifacts", "Registry", "T1204 T1059 T1070.004", &[
        Reg("BAM", &[
            r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            r"HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            r"HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
        ], 1),
        Reg("UserAssist", &[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"], 2),
        Reg("RunDialogAndTypedPaths", &[
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
            r"HKCU\Software\Microsoft\Internet Explorer\TypedURLs",
        ], 0),
        Reg("CompatibilityAssistant", &[
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        ], 0),
        Reg("MuiCache", &[r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"], 0),
        Reg("InstalledSoftware", &[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ], 1),
        Reg("UacPolicy", &[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"], 1),
    ]),
    c("Registry_Hives", "Registry", "T1003.002 T1112", &[
        Native("Hives", native::hive_export),
        // Amcache and SRUM are locked ESE/hive files: esentutl copies them through VSS.
        Cmd("Amcache", "esentutl.exe", &["/y", r"{drive}\Windows\AppCompat\Programs\Amcache.hve", "/vss", "/d", r"{raw}\Amcache.hve"]),
    ]),
    // ---------------------------------------------------------------- file system
    c("Prefetch", "FileSystem", "T1204 T1070.004", &[
        Files("PrefetchFiles", &[r"%SystemRoot%\Prefetch"], &["*.pf"], 0, false),
        Copy("PrefetchRaw", &[r"%SystemRoot%\Prefetch"], &["*.pf", "*.db"], 0),
        Reg("Parameters", &[r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"], 0),
    ]),
    c("User_Activity", "FileSystem", "T1204.002 T1074 T1566", &[
        Files("RecentItems", &[r"{users}\AppData\Roaming\Microsoft\Windows\Recent"], &["*.lnk"], 0, false),
        Files("JumpLists", &[
            r"{users}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
            r"{users}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations",
        ], ANY, 0, false),
        Copy("RecentRaw", &[r"{users}\AppData\Roaming\Microsoft\Windows\Recent"], ANY, 1),
        Files("StagingExecutables", &[
            r"{users}\Downloads", r"{users}\Desktop", r"{users}\AppData\Local\Temp", r"{users}\AppData\Roaming",
            r"%SystemRoot%\Temp", r"%PUBLIC%", r"%ProgramData%",
        ], EXECUTABLES, 2, true),
        Files("RecycleBin", &[r"%SystemDrive%\$Recycle.Bin"], &["$I*"], 2, false),
        Copy("RecycleBinIndex", &[r"%SystemDrive%\$Recycle.Bin"], &["$I*"], 2),
        Files("WindowsTimeline", &[r"{users}\AppData\Local\ConnectedDevicesPlatform"], &["ActivitiesCache.db*"], 2, false),
        Copy("WindowsTimelineRaw", &[r"{users}\AppData\Local\ConnectedDevicesPlatform"], &["ActivitiesCache.db*"], 2),
    ]),
    c("SRUM", "FileSystem", "T1049 T1204", &[
        Files("Database", &[r"%SystemRoot%\System32\sru"], ANY, 0, false),
        Cmd("SrumDb", "esentutl.exe", &["/y", r"{drive}\Windows\System32\sru\SRUDB.dat", "/vss", "/d", r"{raw}\SRUDB.dat"]),
    ]),
    c("NTFS", "FileSystem", "T1070.004 T1490 T1006", &[
        Cmd("NtfsInfo", "fsutil.exe", &["fsinfo", "ntfsinfo", "{drive}"]),
        Cmd("UsnJournal", "fsutil.exe", &["usn", "queryjournal", "{drive}"]),
        Cmd("ShadowCopies", "vssadmin.exe", &["list", "shadows"]),
        Cmd("ShadowStorage", "vssadmin.exe", &["list", "shadowstorage"]),
        Ps("ShadowCopyObjects", "Get-CimInstance Win32_ShadowCopy|ForEach-Object{[pscustomobject]@{ID=$_.ID;Volume=$_.VolumeName;
            Device=$_.DeviceObject;Created=T $_.InstallDate;ClientAccessible=$_.ClientAccessible;Persistent=$_.Persistent}}"),
        Ps("Volumes", "Get-Volume|Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,Size,SizeRemaining"),
    ]),
    c("USB_Devices", "Devices", "T1091 T1052.001 T1200", &[
        Reg("UsbStor", &[r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"], 2),
        Reg("Usb", &[r"HKLM\SYSTEM\CurrentControlSet\Enum\USB"], 2),
        Reg("MountedDevices", &[r"HKLM\SYSTEM\MountedDevices"], 0),
        Reg("PortableDevices", &[r"HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices"], 1),
        Reg("MountPoints", &[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"], 1),
        Ps("Present", "Get-PnpDevice -PresentOnly|Where-Object{'USB','DiskDrive','CDROM','Image','Biometric','Bluetooth','Net','WPD' -contains $_.Class}|
            Select-Object Class,FriendlyName,InstanceId,Status,Manufacturer"),
        Copy("SetupApiLog", &[r"%SystemRoot%\INF"], &["setupapi.dev*.log"], 0),
    ]),
    // ---------------------------------------------------------------- applications
    c("Browser", "Applications", "T1217 T1176 T1189", &[
        Files("ProfileDatabases", &[
            r"{users}\AppData\Local\Google\Chrome\User Data\*",
            r"{users}\AppData\Local\Microsoft\Edge\User Data\*",
            r"{users}\AppData\Local\BraveSoftware\Brave-Browser\User Data\*",
            r"{users}\AppData\Roaming\Mozilla\Firefox\Profiles\*",
        ], &["History", "Bookmarks", "Preferences", "Secure Preferences", "places.sqlite", "extensions.json", "downloads.sqlite"], 0, true),
        // Browsing history only. Credential and cookie stores (Login Data, Cookies) are not copied.
        Copy("History", &[
            r"{users}\AppData\Local\Google\Chrome\User Data\*",
            r"{users}\AppData\Local\Microsoft\Edge\User Data\*",
            r"{users}\AppData\Local\BraveSoftware\Brave-Browser\User Data\*",
            r"{users}\AppData\Roaming\Mozilla\Firefox\Profiles\*",
        ], &["History", "Bookmarks", "places.sqlite", "extensions.json"], 0),
        Text("ExtensionManifests", &[
            r"{users}\AppData\Local\Google\Chrome\User Data\*\Extensions",
            r"{users}\AppData\Local\Microsoft\Edge\User Data\*\Extensions",
        ], &["manifest.json"], 2),
    ]),
    c("Email_Office", "Applications", "T1566.001 T1204.002 T1137 T1114", &[
        Files("MailStores", &[r"{users}\AppData\Local\Microsoft\Outlook", r"{users}\Documents\Outlook Files"], &["*.pst", "*.ost"], 1, false),
        Files("MacroDocuments", &[r"{users}\Documents", r"{users}\Desktop", r"{users}\Downloads", r"{users}\AppData\Local\Temp"],
            &["*.xlsm", "*.xlsb", "*.docm", "*.dotm", "*.pptm", "*.potm", "*.xltm", "*.xlam", "*.one"], 3, true),
        Reg("OfficeSecurity", &[r"HKCU\SOFTWARE\Microsoft\Office\*\*\Security", r"HKCU\SOFTWARE\Policies\Microsoft\Office\*\*\Security"], 2),
        Reg("RecentDocuments", &[r"HKCU\SOFTWARE\Microsoft\Office\*\*\File MRU", r"HKCU\SOFTWARE\Microsoft\Office\*\*\User MRU"], 2),
        Reg("OutlookConfiguration", &[
            r"HKCU\SOFTWARE\Microsoft\Office\*\Outlook\Options\Mail",
            r"HKCU\SOFTWARE\Microsoft\Office\*\Outlook\Security",
            r"HKCU\SOFTWARE\Microsoft\Office\*\Outlook\Addins",
        ], 1),
        RegNames("OutlookProfiles", &[r"HKCU\SOFTWARE\Microsoft\Office\*\Outlook\Profiles"]),
        Files("OfficeStartup", &[
            r"{users}\AppData\Roaming\Microsoft\Word\STARTUP",
            r"{users}\AppData\Roaming\Microsoft\Excel\XLSTART",
            r"{users}\AppData\Roaming\Microsoft\Templates",
            r"{users}\AppData\Roaming\Microsoft\AddIns",
        ], ANY, 1, true),
    ]),
    c("Cloud", "Applications", "T1567.002 T1552.001 T1530", &[
        Reg("OneDriveAccounts", &[r"HKCU\SOFTWARE\Microsoft\OneDrive\Accounts"], 1),
        // Presence and timestamps only: credential file contents are never read.
        Files("CredentialStores", &[
            r"{users}\.aws", r"{users}\.azure", r"{users}\AppData\Roaming\gcloud", r"{users}\.kube", r"{users}\.docker",
        ], ANY, 1, false),
        Files("SyncClients", &[
            r"{users}\AppData\Local\Microsoft\OneDrive\logs",
            r"{users}\AppData\Roaming\Dropbox",
            r"{users}\AppData\Local\Google\DriveFS",
            r"{users}\AppData\Roaming\Microsoft\Teams",
            r"{users}\AppData\Roaming\rclone",
            r"{users}\AppData\Roaming\MEGAsync",
        ], ANY, 1, false),
    ]),
    c("AI_Tooling", "Applications", "T1588 T1059", &[
        Files("ModelFiles", &[
            r"{users}\.ollama\models", r"{users}\.cache\huggingface", r"{users}\.cache\lm-studio\models",
            r"{users}\.lmstudio\models", r"{users}\AppData\Local\nomic.ai", r"{users}\Downloads", r"{users}\Documents",
        ], &["*.gguf", "*.ggml", "*.safetensors", "*.onnx"], 4, false),
        Files("ToolInstalls", &[
            r"{users}\AppData\Local\Programs\Ollama", r"{users}\AppData\Local\Programs\LM Studio", r"{users}\AppData\Local\Programs\Jan",
            r"{users}\AppData\Local\AnthropicClaude", r"{users}\.claude", r"{users}\.cursor", r"{users}\.codex",
        ], &["*.exe", "*.json"], 1, false),
        Reg("RegistryKeys", &[
            r"HKCU\Software\Ollama", r"HKLM\SOFTWARE\Ollama", r"HKCU\Software\LM Studio", r"HKLM\SOFTWARE\LM Studio",
            r"HKCU\Software\GPT4All", r"HKCU\Software\OpenAI", r"HKCU\Software\Anthropic",
        ], 1),
    ]),
    c("Web_Server", "Applications", "T1505.003 T1190", &[
        Files("WebContent", &[r"%SystemDrive%\inetpub", r"%SystemDrive%\xampp\htdocs", r"%SystemDrive%\wamp64\www"],
            &["*.asp", "*.aspx", "*.ashx", "*.asmx", "*.php", "*.php5", "*.php7", "*.phtml", "*.jsp", "*.jspx", "*.cfm", "*.shtml", "*.config"], 6, true),
        Files("IisLogs", &[r"%SystemDrive%\inetpub\logs\LogFiles", r"%SystemRoot%\System32\LogFiles\HTTPERR"], &["*.log"], 2, false),
        Copy("IisLogsRaw", &[r"%SystemDrive%\inetpub\logs\LogFiles", r"%SystemRoot%\System32\LogFiles\HTTPERR"], &["*.log"], 2),
        Text("IisConfiguration", &[r"%SystemRoot%\System32\inetsrv\config"], &["applicationHost.config"], 0),
    ]),
    c("SQL_Server", "Applications", "T1505.001 T1059.003", &[
        Reg("Instances", &[r"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server", r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server"], 1),
        Ps("Services", "Get-CimInstance Win32_Service|Where-Object{$_.Name -match '(?i)sql'}|Select-Object Name,DisplayName,State,StartMode,PathName,StartName"),
        Files("ErrorLogs", &[r"%ProgramFiles%\Microsoft SQL Server\*\MSSQL\Log"], &["ERRORLOG*"], 0, false),
        Copy("ErrorLogsRaw", &[r"%ProgramFiles%\Microsoft SQL Server\*\MSSQL\Log"], &["ERRORLOG*"], 0),
    ]),
    c("Windows_Apps", "Applications", "T1204 T1553", &[
        Ps("AppxPackages", "Get-AppxPackage -AllUsers|Select-Object Name,Publisher,Version,InstallLocation,
            @{n='Signature';e={[string]$_.SignatureKind}},IsFramework,IsDevelopmentMode,@{n='Users';e={@($_.PackageUserInformation|ForEach-Object{[string]$_.UserSecurityId})}}"),
        Reg("DeveloperMode", &[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"], 0),
        Ps("DeploymentEvents", "Ev 'Microsoft-Windows-AppXDeployment-Server/Operational' @(400,401,404,701) 500"),
    ]),
    c("Virtualization", "Applications", "T1564.006 T1610", &[
        Cmd("WslDistributions", "wsl.exe", &["--list", "--verbose"]),
        Reg("WslRegistrations", &[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss"], 1),
        Files("WslDisks", &[r"{users}\AppData\Local\Packages\*\LocalState"], &["*.vhdx"], 0, false),
        Ps("HyperVMachines", "Get-VM|ForEach-Object{[pscustomobject]@{Name=$_.Name;State=[string]$_.State;Generation=$_.Generation;
            Created=T $_.CreationTime;Uptime=[string]$_.Uptime;Path=$_.Path;Disks=@((Get-VMHardDiskDrive -VMName $_.Name).Path)}}"),
        Ps("HyperVCheckpoints", "Get-VM|Get-VMSnapshot|ForEach-Object{[pscustomobject]@{VM=$_.VMName;Name=$_.Name;Created=T $_.CreationTime}}"),
        Cmd("DockerContainers", "docker.exe", &["ps", "-a", "--no-trunc"]),
    ]),
    // ---------------------------------------------------------------- platform and domain
    c("Platform_Security", "Platform", "T1542 T1553.006 T1556", &[
        Ps("Tpm", "Get-Tpm|Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,ManufacturerIdTxt,ManufacturerVersion"),
        Ps("SecureBoot", "[pscustomobject]@{SecureBootEnabled=$(try{Confirm-SecureBootUEFI -ErrorAction Stop}catch{[string]$_.Exception.Message})}"),
        Ps("BitLocker", "Get-BitLockerVolume|ForEach-Object{[pscustomobject]@{Mount=$_.MountPoint;Status=[string]$_.VolumeStatus;
            Protection=[string]$_.ProtectionStatus;Method=[string]$_.EncryptionMethod;Percent=$_.EncryptionPercentage;
            Protectors=@($_.KeyProtector|ForEach-Object{[string]$_.KeyProtectorType})}}"),
        Ps("DeviceGuard", "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard|
            Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus"),
        Cmd("DeviceJoin", "dsregcmd.exe", &["/status"]),
        Reg("BootAndIntegrity", &[
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
        ], 2),
        Reg("WindowsHello", &[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin",
            r"HKLM\SOFTWARE\Policies\Microsoft\Biometrics",
            r"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork",
        ], 2),
        RegNames("IdentityCache", &[r"HKLM\SOFTWARE\Microsoft\IdentityStore\LogonCache"]),
        Files("WdacPolicies", &[r"%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active", r"%SystemRoot%\System32\CodeIntegrity"], &["*.cip", "*.p7b"], 0, true),
    ]),
    c("Active_Directory", "Domain", "T1558.003 T1003.006 T1484.001 T1482", &[
        Cmd("DomainTrusts", "nltest.exe", &["/domain_trusts"]),
        Cmd("DomainController", "nltest.exe", &["/dsgetdc:"]),
        Cmd("AppliedPolicy", "gpresult.exe", &["/r", "/scope", "computer"]),
        Cmd("TicketGrantingTicket", "klist.exe", &["tgt"]),
        Ps("ServiceTicketRequests", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769;StartTime=$since} -MaxEvents 5000|
            ForEach-Object{$p=$_.Properties;[pscustomobject]@{Time=T $_.TimeCreated;Account=$p[0].Value;Service=$p[2].Value;
              Encryption=('0x{0:x}' -f $p[5].Value);ClientIP=$p[6].Value;Status=('0x{0:x}' -f $p[8].Value)}}"),
        Ps("DirectoryReplicationAccess", "Ev 'Security' 4662 2000 1500"),
        Ps("DirectoryServiceEvents", "Ev 'Directory Service' @(1168,1173,2089,2887,2889) 500"),
        Reg("Configuration", &[
            r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
            r"HKLM\SYSTEM\CurrentControlSet\Services\ldap",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History",
        ], 2),
        Reg("Laps", &[
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS",
            r"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd",
            r"HKLM\SOFTWARE\Microsoft\Policies\LAPS",
        ], 2),
        Files("GroupPolicyCache", &[r"%SystemRoot%\System32\GroupPolicy", r"%ProgramData%\Microsoft\Group Policy\History"],
            &["*.bat", "*.cmd", "*.ps1", "*.vbs", "*.wsf", "*.js", "*.exe", "*.dll", "*.ini", "*.xml", "*.pol"], 6, true),
        Copy("GroupPolicyScripts", &[r"%SystemRoot%\System32\GroupPolicy", r"%ProgramData%\Microsoft\Group Policy\History"],
            &["*.bat", "*.cmd", "*.ps1", "*.vbs", "*.wsf", "*.js", "*.ini", "*.xml"], 6),
        Files("NtdsDatabase", &[r"%SystemRoot%\NTDS"], ANY, 0, false),
    ]),
    // ---------------------------------------------------------------- forward-in-time capture: last
    live("Packet_Capture", "LiveCapture", "T1071 T1041 T1095", &[Native("Capture", native::packet_capture)]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn collector_and_probe_names_are_unique_and_filename_safe() {
        let mut names = HashSet::new();
        for col in CATALOG {
            assert!(names.insert(col.name), "duplicate collector {}", col.name);
            assert!(col.name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_'), "{}", col.name);
            assert!(!col.probes.is_empty(), "{} has no probes", col.name);
            let mut probes = HashSet::new();
            for p in col.probes {
                assert!(probes.insert(p.name()), "duplicate probe {}.{}", col.name, p.name());
                assert!(p.name().chars().all(|ch| ch.is_ascii_alphanumeric()), "{}.{}", col.name, p.name());
            }
        }
    }

    #[test]
    fn powershell_bodies_are_command_line_safe() {
        for col in CATALOG {
            for p in col.probes {
                if let Ps(name, body) = p {
                    assert!(!body.contains('"'), "{}.{name} contains a double quote", col.name);
                    assert!(!body.contains('#'), "{}.{name} contains a comment", col.name);
                    let (open, close) = (body.matches('{').count(), body.matches('}').count());
                    assert_eq!(open, close, "{}.{name} has unbalanced braces", col.name);
                    let (open, close) = (body.matches('(').count(), body.matches(')').count());
                    assert_eq!(open, close, "{}.{name} has unbalanced parentheses", col.name);
                    assert_eq!(body.matches('\'').count() % 2, 0, "{}.{name} has an unbalanced quote", col.name);
                }
            }
        }
    }

    #[test]
    fn volatile_state_is_collected_before_disk_artifacts() {
        let pos = |n: &str| CATALOG.iter().position(|col| col.name == n).unwrap();
        assert_eq!(pos("RAM_Dump"), 0);
        assert!(pos("Processes") < pos("Network_State"));
        assert!(pos("Network_State") < pos("EventLog_Security"));
        assert!(pos("EventLog_Security") < pos("Registry_Hives"));
        assert_eq!(pos("Packet_Capture"), CATALOG.len() - 1);
    }

    #[test]
    fn only_live_collectors_change_system_state() {
        let live: Vec<&str> = CATALOG.iter().filter(|col| col.live).map(|col| col.name).collect();
        assert_eq!(live, ["RAM_Dump", "Packet_Capture"]);
    }
}
