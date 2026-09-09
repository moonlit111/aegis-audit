param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Continue'

function Read-Session {
    $path = Join-Path $InputPath 'session.json'
    try {
        $value = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($value.schema_version -ne 1 -or -not $value.session_id) {
            throw 'invalid session document'
        }
        return $value
    } catch {
        throw "Cannot read session document: $($_.Exception.Message)"
    }
}

function Test-Write {
    param([string]$Path, [string]$Value)
    $errorText = $null
    $allowed = $false
    try {
        Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII -ErrorAction Stop
        $allowed = Test-Path -LiteralPath $Path -PathType Leaf
    } catch {
        $errorText = $_.Exception.Message
    }
    [ordered]@{ allowed = [bool]$allowed; error = $errorText }
}

function Test-Dns {
    param([string]$HostName)
    $errorText = $null
    $succeeded = $false
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
        $succeeded = @($addresses).Count -gt 0
    } catch {
        $errorText = $_.Exception.Message
    }
    [ordered]@{ succeeded = [bool]$succeeded; error = $errorText }
}

function Test-Tcp {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs)
    $errorText = $null
    $succeeded = $false
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.ConnectAsync($HostName, $Port)
        $completed = $connect.Wait($TimeoutMs)
        $succeeded = $completed -and $client.Connected
        if (-not $succeeded -and -not $errorText) {
            $errorText = 'connection did not complete before timeout'
        }
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        $client.Dispose()
    }
    [ordered]@{ succeeded = [bool]$succeeded; error = $errorText }
}

$session = Read-Session
$sessionId = [string]$session.session_id
$forbiddenPath = Join-Path $InputPath 'forbidden-write.txt'
$markerPath = Join-Path $OutputPath 'output-marker.txt'

$inputWrite = Test-Write -Path $forbiddenPath -Value 'must-not-persist'
$outputWrite = Test-Write -Path $markerPath -Value "session=$sessionId"

$dns = Test-Dns -HostName 'www.example.com'
$tcp = Test-Tcp -HostName '1.1.1.1' -Port 443 -TimeoutMs 1500
$routeError = $null
$defaultRoutes = @()
try {
    $defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
} catch {
    $routeError = $_.Exception.Message
}

$dnsServers = @()
try {
    $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.ServerAddresses } |
        Where-Object { $_ })
} catch {
    $dnsServers = @()
}

$os = Get-CimInstance Win32_OperatingSystem
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$observation = [ordered]@{
    schema_version = 1
    session_id = $sessionId
    guest = [ordered]@{
        os_caption = [string]$os.Caption
        os_version = [string]$os.Version
        architecture = [string]$os.OSArchitecture
        processor_architecture = $env:PROCESSOR_ARCHITECTURE
        computer_name = $env:COMPUTERNAME
        user = $identity.Name
    }
    input_write = $inputWrite
    output_write = $outputWrite
    network = [ordered]@{
        dns = $dns
        tcp = $tcp
        default_route_present = [bool]($defaultRoutes.Count -gt 0)
        default_route_count = $defaultRoutes.Count
        route_error = $routeError
        dns_server_count = $dnsServers.Count
    }
}

$observationPath = Join-Path $OutputPath 'guest-observation.json'
$observation | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $observationPath -Encoding UTF8

$receipt = [ordered]@{
    schema_version = 1
    run_id = [string]$session.run_id
    attempt_id = [string]$session.attempt_id
    session_id = $sessionId
    status = 'COMPLETED'
}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputPath 'session.json') -Encoding UTF8

# The guest is disposable. Shut it down after the observation is flushed; this
# command runs inside Windows Sandbox and never restarts or shuts down the host.
& "$env:SystemRoot\System32\shutdown.exe" /s /t 3
