param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$LLVMPath = 'C:\Users\WDAGUtilityAccount\Desktop\AegisLLVM'

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
    if ($config.mode -ne 'FUZZ' -or
        $config.adapter -ne 'WINDOWS_LIBFUZZER_PREBUILT') {
        throw 'the libFuzzer runner requires FUZZ mode and the prebuilt adapter'
    }
    if (-not (Test-RelativePath $config.target_path)) {
        throw 'unsafe libFuzzer target path'
    }
    if ($config.entry.path -ne $config.target_path) {
        throw 'the command entry must execute the declared target'
    }
    if (-not $config.fuzz -or $config.fuzz.engine -ne 'LLVM_LIBFUZZER') {
        throw 'LLVM_LIBFUZZER options are required'
    }

    $target = Join-Path $InputPath $config.target_path
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw 'libFuzzer target is missing'
    }
    $runtime = Join-Path $LLVMPath 'lib/clang/23/lib/windows'
    if (-not (Test-Path -LiteralPath $runtime -PathType Container)) {
        throw 'LLVM runtime is missing'
    }
    $env:PATH = "$runtime;$env:PATH"

    $work = Join-Path $env:TEMP ('aegis-libfuzzer-' + [guid]::NewGuid().ToString('N'))
    $corpus = Join-Path $work 'corpus'
    New-Item -ItemType Directory -Path $corpus | Out-Null
    $seedPath = Join-Path $corpus 'seed'
    $seedValue = ''
    if ($config.baseline_inputs.Count -gt 0 -and
        $config.baseline_inputs[0].type -eq 'STDIN') {
        $seedValue = [string]$config.baseline_inputs[0].value
    }
    Set-Content -LiteralPath $seedPath -Value $seedValue -Encoding ASCII -NoNewline

    $fuzzerStdoutPath = Join-Path $OutputPath 'fuzzer.stdout.log'
    $fuzzerStderrPath = Join-Path $OutputPath 'fuzzer.stderr.log'
    New-Item -ItemType File -Path $fuzzerStdoutPath, $fuzzerStderrPath -Force | Out-Null
    $fuzzArguments = @(
        "-runs=$($config.fuzz.runs)",
        "-seed=$($config.fuzz.random_seed)",
        "-max_len=$($config.fuzz.max_input_bytes)",
        "-timeout=$($config.fuzz.timeout_seconds)",
        "-artifact_prefix=$OutputPath/",
        $corpus
    )
    $process = Start-Process -FilePath $target -ArgumentList $fuzzArguments `
        -WorkingDirectory $work -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $fuzzerStdoutPath `
        -RedirectStandardError $fuzzerStderrPath
    $fuzzExitCode = $process.ExitCode

    $crashPath = Join-Path $OutputPath 'crash-input.bin'
    if (-not (Test-Path -LiteralPath $crashPath -PathType Leaf)) {
        $crashPath = $null
    }

    $replayExitCode = $null
    $replayReproduced = $false
    if ($crashPath) {
        $replayStdoutPath = Join-Path $OutputPath 'replay.stdout.log'
        $replayStderrPath = Join-Path $OutputPath 'replay.stderr.log'
        New-Item -ItemType File -Path $replayStdoutPath, $replayStderrPath -Force | Out-Null
        $replay = Start-Process -FilePath $target -ArgumentList @($crashPath) `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $replayStdoutPath `
            -RedirectStandardError $replayStderrPath
        $replayExitCode = $replay.ExitCode
        $replayReproduced = $replayExitCode -ne 0
    }

    $corpusArchive = Join-Path $OutputPath 'corpus.zip'
    if (Test-Path -LiteralPath $corpusArchive) {
        Remove-Item -LiteralPath $corpusArchive -Force
    }
    Compress-Archive -Path (Join-Path $corpus '*') -DestinationPath $corpusArchive

    $fuzzerStderr = Get-Content -LiteralPath $fuzzerStderrPath -Raw -ErrorAction SilentlyContinue
    $coverageLine = ($fuzzerStderr -split "`n" | Where-Object { $_ -match 'cov:' } | Select-Object -Last 1)
    $observation = [ordered]@{
        schema_version = 1
        session_id = [string]$session.session_id
        adapter = [string]$config.adapter
        target_path = [string]$config.target_path
        engine = 'LLVM libFuzzer'
        engine_exit_code = [int]$fuzzExitCode
        runs = [int]$config.fuzz.runs
        random_seed = [int64]$config.fuzz.random_seed
        max_input_bytes = [int]$config.fuzz.max_input_bytes
        coverage_feedback = 'inline-8bit-counters'
        coverage_line = [string]$coverageLine
        crash_found = [bool]$crashPath
        crash_input = if ($crashPath) { 'crash-input.bin' } else { $null }
        replay_exit_code = if ($null -ne $replayExitCode) { [int]$replayExitCode } else { $null }
        replay_reproduced = [bool]$replayReproduced
        corpus_archive = 'corpus.zip'
        stdout_file = 'fuzzer.stdout.log'
        stderr_file = 'fuzzer.stderr.log'
    }
    $observation | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'guest-observation.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $OutputPath 'fuzz-executed.txt') `
        -Value "session=$($session.session_id);exit=$fuzzExitCode;crash=$([bool]$crashPath)" -Encoding ASCII

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
