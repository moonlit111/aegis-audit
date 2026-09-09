param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$PythonPath = 'C:\Users\WDAGUtilityAccount\Desktop\AegisPython'

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
    if ($config.mode -ne 'VERIFY' -or $config.adapter -ne 'WINDOWS_PYTHON_CALL') {
        throw 'the Windows Python runner requires VERIFY mode and the Python adapter'
    }
    if (-not (Test-RelativePath $config.entry.module)) {
        throw 'unsafe Python module path'
    }
    $modulePath = Join-Path $InputPath $config.entry.module
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw 'Python module is missing'
    }
    $python = Join-Path $PythonPath 'python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'Python runtime is missing'
    }

    $code = @"
import importlib.util
spec = importlib.util.spec_from_file_location("aegis_target", r"$modulePath")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.$($config.entry.function)())
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($code))
    $command = "import base64; exec(base64.b64decode('$encoded').decode('utf-8'))"
    $stdoutPath = Join-Path $OutputPath 'target.stdout.log'
    $stderrPath = Join-Path $OutputPath 'target.stderr.log'
    $stdout = & $python -c $command 2> $stderrPath
    Set-Content -LiteralPath $stdoutPath -Value ([string]::Join("`n", @($stdout))) -Encoding ASCII
    $exitCode = $LASTEXITCODE

    $observation = [ordered]@{
        schema_version = 1
        session_id = [string]$session.session_id
        adapter = [string]$config.adapter
        target_path = [string]$config.target_path
        module = [string]$config.entry.module
        function = [string]$config.entry.function
        entry = 'FUNCTION'
        exit_code = [int]$exitCode
        stdout_file = 'target.stdout.log'
        stderr_file = 'target.stderr.log'
    }
    $observation | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'guest-observation.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $OutputPath 'target-executed.txt') `
        -Value "session=$($session.session_id);exit=$exitCode" -Encoding ASCII

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

& "$env:SystemRoot\System32\shutdown.exe" /s /t 3
