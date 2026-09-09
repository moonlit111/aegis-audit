param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$ZigPath = 'C:\Users\WDAGUtilityAccount\Desktop\AegisZig'

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
    if ($config.mode -ne 'VERIFY' -or $config.adapter -ne 'WINDOWS_NATIVE_SOURCE') {
        throw 'the native-source runner requires VERIFY mode and the native-source adapter'
    }
    if (-not (Test-RelativePath $config.target_path)) {
        throw 'unsafe native-source target path'
    }
    if ($config.entry.path -ne $config.target_path) {
        throw 'the command entry must execute the declared target'
    }

    $target = Join-Path $InputPath $config.target_path
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw 'native source target is missing'
    }
    $zig = Join-Path $ZigPath 'zig.exe'
    if (-not (Test-Path -LiteralPath $zig -PathType Leaf)) {
        throw 'Zig runtime is missing'
    }
    $compilerVersion = (& $zig version) -join ''
    $mode = if ($config.target_path -match '\.c$') { 'cc' } else { 'c++' }

    $work = Join-Path $env:TEMP ('aegis-native-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $globalCache = Join-Path $work 'global-cache'
    $localCache = Join-Path $work 'local-cache'
    New-Item -ItemType Directory -Path $globalCache, $localCache | Out-Null
    $env:ZIG_GLOBAL_CACHE_DIR = $globalCache
    $env:ZIG_LOCAL_CACHE_DIR = $localCache
    $compiled = Join-Path $work 'target.exe'
    $compileStdoutPath = Join-Path $OutputPath 'compile.stdout.log'
    $compileStderrPath = Join-Path $OutputPath 'compile.stderr.log'
    New-Item -ItemType File -Path $compileStdoutPath, $compileStderrPath -Force | Out-Null
    $compileStdout = & $zig $mode -O0 $target -o $compiled 2> $compileStderrPath
    Set-Content -LiteralPath $compileStdoutPath -Value ([string]::Join("`n", @($compileStdout))) -Encoding ASCII
    $compileExitCode = $LASTEXITCODE
    if ($compileExitCode -ne 0 -or -not (Test-Path -LiteralPath $compiled -PathType Leaf)) {
        throw "native-source compile failed with exit code $compileExitCode"
    }

    $arguments = @($config.entry.arguments)
    $targetStdoutPath = Join-Path $OutputPath 'target.stdout.log'
    $targetStderrPath = Join-Path $OutputPath 'target.stderr.log'
    New-Item -ItemType File -Path $targetStdoutPath, $targetStderrPath -Force | Out-Null
    $targetStdout = & $compiled @arguments 2> $targetStderrPath
    Set-Content -LiteralPath $targetStdoutPath -Value ([string]::Join("`n", @($targetStdout))) -Encoding ASCII
    $targetExitCode = $LASTEXITCODE

    $observation = [ordered]@{
        schema_version = 1
        session_id = [string]$session.session_id
        adapter = [string]$config.adapter
        target_path = [string]$config.target_path
        entry = 'COMMAND_LINE'
        arguments = $arguments
        compiler = "zig $compilerVersion"
        compile_exit_code = [int]$compileExitCode
        exit_code = [int]$targetExitCode
        compile_stdout_file = 'compile.stdout.log'
        compile_stderr_file = 'compile.stderr.log'
        stdout_file = 'target.stdout.log'
        stderr_file = 'target.stderr.log'
    }
    $observation | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'guest-observation.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $OutputPath 'target-executed.txt') `
        -Value "session=$($session.session_id);compile=$compileExitCode;exit=$targetExitCode" -Encoding ASCII

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
