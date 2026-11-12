$ErrorActionPreference = "Stop"

# Windows Server 2012 R2 / Windows 8 ship PowerShell 4, whose default security
# protocol is still TLS 1.0; GitHub only accepts TLS 1.2+. Newer .NET reports
# SystemDefault (0), which already negotiates the best protocol, so TLS 1.2 is
# only added when an explicit protocol list is configured.
$cfSecurityProtocol = [int][Net.ServicePointManager]::SecurityProtocol
if ($cfSecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]($cfSecurityProtocol -bor [int][Net.SecurityProtocolType]::Tls12)
}

# Installing/uninstalling writes to C:\Program Files and registers a SYSTEM
# scheduled task, both of which require an elevated (administrator) session.
# Fail fast with a clear prompt instead of a raw "Access is denied" later.
$cfPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $cfPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] 安装或卸载 cf-probe 需要管理员权限。" -ForegroundColor Red
    Write-Host "请右键点击 PowerShell，选择“以管理员身份运行”，然后重新执行本命令。" -ForegroundColor Yellow
    exit 1
}

$Repo = "emailtq/cfsm-agent"
$GitHubProxy = ""
$InstallVersion = "latest"
$InstallNodeToken = ""

$needValueFor = ""
foreach ($arg in $args) {
    if ($needValueFor) {
        switch ($needValueFor) {
            "proxy" { $GitHubProxy = $arg }
            "version" { $InstallVersion = $arg }
        }
        $needValueFor = ""
        continue
    }
    switch -Regex ($arg) {
        "^--install-node-token=(.*)$" { $InstallNodeToken = $Matches[1]; continue }
        "^(?:--?secret|--?terminal-token-file|--install-terminal-token)(?:=|$)" { throw "Legacy credentials removed; reinstall with -token." }
        "^--install-ghproxy=(.+)$" { $GitHubProxy = $Matches[1]; continue }
        "^--install-ghproxy$" { $needValueFor = "proxy"; continue }
        "^--install-version=(.+)$" { $InstallVersion = $Matches[1]; continue }
        "^--install-version$" { $needValueFor = "version"; continue }
    }
}

function Get-ArchName {
    # PROCESSOR_ARCHITECTURE is emulated on Windows ARM64 (amd64 processes
    # under Prism see "AMD64"), so prefer the true native architecture.
    if ($env:PROCESSOR_ARCHITEW6432) {
        switch ($env:PROCESSOR_ARCHITEW6432) {
            "ARM64" { "arm64"; return }
            "ARM64EC" { "arm64"; return }
            "AMD64" { "amd64"; return }
            "x86" { "386"; return }
        }
    }
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        # 0=x86 1=MIPS 2=Alpha 6=IA64 9=x64 12=ARM64
        if ($cpu.DeviceArchitecture -eq 12) { "arm64"; return }
        if ($cpu.DeviceArchitecture -eq 9) { "amd64"; return }
    } catch {
        # Fall through to the environment variable below.
    }
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "amd64"; break }
        "ARM64" { "arm64"; break }
        "x86" { "386"; break }
        default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Test-PrivateNodeTokenParent([string]$Path) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $trusted = @($user, 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $parent = [IO.Path]::GetFullPath((Split-Path -Parent $Path))
    $immediate = $true
    while ($parent) {
        $item = Get-Item -LiteralPath $parent -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unsafe node token parent." }
        $acl = Get-Acl -LiteralPath $parent
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { throw "Untrusted node token parent owner." }
        $mask = [uint32]0x500D0040 # generic write/all, DELETE/WRITE_DAC/WRITE_OWNER, DELETE_CHILD
        if ($immediate) { $mask = $mask -bor 6 }
        foreach ($rule in $acl.Access) {
            if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            $rights = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$rule.FileSystemRights), 0)
            if ($sid -notin $trusted -and ($rights -band $mask)) { throw "Replaceable node token parent." }
        }
        $next = [IO.Path]::GetDirectoryName($parent)
        if (-not $next -or $next -eq $parent) { break }
        $parent = $next
        $immediate = $false
    }
}

function New-PrivateNodeTokenFile([string]$Token) {
    if ($Token -cnotmatch '^[a-f0-9]{64}$') { throw "Invalid node token." }
    $dir = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
    try { Test-PrivateNodeTokenParent $dir } catch {
        $homePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if (-not $homePath) { throw "No safe node token staging directory." }
        $dir = Join-Path $homePath ('.cfsm-node-token-' + [IO.Path]::GetRandomFileName())
        Test-PrivateNodeTokenParent $dir
    }
    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($user.Value, 'S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        # Create with the private ACL, never a briefly writable inherited directory.
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($dir), $acl)
        } else {
            $null = [IO.Directory]::CreateDirectory($dir, $acl)
        }
        $actual = Get-Acl -LiteralPath $dir
        if (-not $actual.AreAccessRulesProtected) { throw "Cannot protect node token ACL." }
        foreach ($rule in $actual.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -notin @($user.Value, 'S-1-5-18', 'S-1-5-32-544')) { throw "Unsafe node token ACL." }
        }
        $file = Join-Path $dir 'node-token'
        Test-PrivateNodeTokenParent $file
        [IO.File]::WriteAllText($file, $Token, [Text.Encoding]::ASCII)
        return $file
    } catch {
        Remove-Item -LiteralPath $dir -Force
        throw "Cannot stage a private node token."
    }
}

function Get-PayloadArguments($Arguments, $TokenSupported, $NodeTokenFile) {
    if (-not $TokenSupported) { throw "This Agent release does not support node tokens; choose a token-capable release." }
    foreach ($arg in $Arguments) {
        if ($arg -match '^--install-node-token=') { continue }
        if ($arg -eq "-terminal=1") { throw "Terminal is supported only on Linux." }
        if ($NodeTokenFile -and $arg -match '^--?(?:token|token-file|register-key)=') { throw "Node credential options conflict." }
        $arg
    }
    if ($NodeTokenFile) { "-token-file=$NodeTokenFile" }
}

$command = if ($args.Count -gt 0) { $args[0] } else { "install" }
$payloadArgs = @($args)
if ($command -in @("uninstall", "remove", "delete", "purge")) {
    Write-Host "[INFO] downloading temporary uninstaller"
    $payloadArgs = @($command)
}

$arch = Get-ArchName
$asset = "cf-probe-windows-$arch.exe"
$path = if ($InstallVersion -eq "latest") { "latest/download" } else { "download/$InstallVersion" }
$url = "https://github.com/$Repo/releases/$path/$asset"
if ($GitHubProxy) {
    $url = $GitHubProxy.TrimEnd("/") + "/" + $url
}

$tmp = Join-Path $env:TEMP "cf-probe-bootstrap-$PID.exe"
Write-Host "CF-Server-Monitor Go Probe bootstrap"
Write-Host "  repo    : $Repo"
Write-Host "  version : $InstallVersion"
Write-Host "  target  : windows/$arch"
Write-Host "  asset   : $asset"
Write-Host "  url     : $url"

$nodeTokenFile = $null
try {
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    if ($command -notin @("uninstall", "remove", "delete", "purge")) {
        $help = @(& $tmp help 2>$null)
        $tokenSupported = [bool]($help | Select-String -SimpleMatch "-token-file=") -and [bool]($help | Select-String -SimpleMatch "-register-key=")
        if ($InstallNodeToken) { $nodeTokenFile = New-PrivateNodeTokenFile $InstallNodeToken }
        $payloadArgs = @(Get-PayloadArguments $payloadArgs $tokenSupported $nodeTokenFile)
    }
    if ($args.Count -eq 0) {
        & $tmp install
    } else {
        & $tmp @payloadArgs
    }
    exit $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    if ($nodeTokenFile) {
        Remove-Item -LiteralPath $nodeTokenFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Split-Path -Parent $nodeTokenFile) -Force -ErrorAction SilentlyContinue
    }
}
