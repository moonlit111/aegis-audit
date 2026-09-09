param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$TinyInstPath = 'C:\Users\WDAGUtilityAccount\Desktop\AegisTinyInst'

function Read-Json {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Test-RelativePath {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or $Path.Length -gt 512) {
        return $false
    }
    if ($Path.Contains('\') -or $Path.Contains(':') -or
        $Path.Contains([char]0) -or $Path.Contains("`n") -or $Path.Contains("`r")) {
        return $false
    }
    foreach ($part in ($Path -split '/')) {
        if ($part -eq '' -or $part -eq '.' -or $part -eq '..') {
            return $false
        }
    }
    return $true
}

function Write-Failure {
    param([string]$Message)
    $error = [ordered]@{
        schema_version = 1
        error = $Message
    }
    $error | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $OutputPath 'guest-error.json') -Encoding UTF8
    $session = Read-Json (Join-Path $InputPath 'session.json')
    $receipt = [ordered]@{
        schema_version = 1
        run_id = [string]$session.run_id
        attempt_id = [string]$session.attempt_id
        session_id = [string]$session.session_id
        status = 'ERROR'
    }
    $receipt | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $OutputPath 'session.json') -Encoding UTF8
}

try {
    $session = Read-Json (Join-Path $InputPath 'session.json')
    $config = Read-Json (Join-Path $InputPath 'runtime-config.json')
    if ($session.schema_version -ne 1 -or $config.schema_version -ne 1) {
        throw 'unsupported sandbox schema'
    }
    if ($config.adapter -ne 'WINDOWS_ORIGINAL_PE32' -and
        $config.adapter -ne 'WINDOWS_ORIGINAL_PE64') {
        throw 'the TinyInst runner requires a Windows PE adapter'
    }
    if (-not (Test-RelativePath $config.target_path)) {
        throw 'unsafe target path'
    }
    if ($config.entry.path -ne $config.target_path) {
        throw 'the command entry must execute the declared target'
    }

    $target = Join-Path $InputPath $config.target_path
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw 'target is missing'
    }
    $engine = Join-Path $TinyInstPath 'litecov.exe'
    if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) {
        throw 'TinyInst engine is missing'
    }

    $coveragePath = Join-Path $OutputPath 'coverage.txt'
    $stdoutPath = Join-Path $OutputPath 'target.stdout.log'
    $stderrPath = Join-Path $OutputPath 'target.stderr.log'
    New-Item -ItemType File -Path $stdoutPath, $stderrPath -Force | Out-Null
    $arguments = @($config.entry.arguments)
    $engineArguments = @(
        '-instrument_module', $config.target_path,
        '-coverage_file', $coveragePath,
        '--', $target
    ) + $arguments
    $process = Start-Process -FilePath $engine -ArgumentList $engineArguments `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
    $exitCode = $process.ExitCode

    $observation = [ordered]@{
        schema_version = 1
        session_id = [string]$session.session_id
        adapter = [string]$config.adapter
        target_path = [string]$config.target_path
        entry = 'COMMAND_LINE'
        arguments = $arguments
        engine = 'TinyInst litecov'
        engine_exit_code = [int]$exitCode
        exit_code = [int]$exitCode
        coverage_file = 'coverage.txt'
        coverage_exists = (Test-Path -LiteralPath $coveragePath -PathType Leaf)
        stdout_file = 'target.stdout.log'
        stderr_file = 'target.stderr.log'
    }
    $observation | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'guest-observation.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $OutputPath 'target-executed.txt') `
        -Value "session=$($session.session_id);engine=$exitCode" -Encoding ASCII

    $receipt = [ordered]@{
        schema_version = 1
        run_id = [string]$session.run_id
        attempt_id = [string]$session.attempt_id
        session_id = [string]$session.session_id
        status = 'COMPLETED'
    }
    $receipt | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $OutputPath 'session.json') -Encoding UTF8
} catch {
    Write-Failure $_.Exception.Message
}
