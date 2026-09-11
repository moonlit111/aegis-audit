param(
    [string]$InputPath,
    [string]$OutputPath,
    [string]$PythonPath,
    [string]$ZigPath,
    [string]$LlvmPath,
    [ValidateSet('ORIGINAL_PE', 'WINDOWS_PYTHON', 'WINDOWS_NATIVE_SOURCE', 'WINDOWS_LIBFUZZER')]
    [string]$Kind
)


function Read-WindowsRuntimeJson {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-WindowsRuntimeJson {
    param([string]$Path, [object]$Value)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Value -Depth 100), $encoding)
}

function Initialize-WindowsRuntimeIO {
    if ('AegisRuntimeCapture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

public sealed class AegisRuntimeCapture {
    private readonly MemoryStream bytes = new MemoryStream();
    private readonly object gate = new object();
    private bool truncated;
    public Task Completion { get; private set; }
    public string Error { get; private set; }
    public bool Truncated { get { lock (gate) { return truncated; } } }
    public string Text {
        get {
            lock (gate) {
                return Encoding.GetEncoding("utf-8", new EncoderReplacementFallback("?"),
                    new DecoderReplacementFallback("?")).GetString(bytes.ToArray());
            }
        }
    }
    public static AegisRuntimeCapture Start(Stream stream, int limit) {
        var capture = new AegisRuntimeCapture();
        capture.Completion = capture.Drain(stream, limit);
        return capture;
    }
    private async Task Drain(Stream stream, int limit) {
        var buffer = new byte[4096];
        try {
            int count;
            while ((count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0) {
                lock (gate) {
                    int keep = Math.Min(count, limit - (int)bytes.Length);
                    bytes.Write(buffer, 0, keep);
                    truncated |= keep < count;
                }
            }
        } catch (Exception error) { Error = error.Message; }
    }
    public static async Task WriteInput(Stream stream, string input) {
        try {
            byte[] data = new UTF8Encoding(false).GetBytes(input ?? "");
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        } finally { stream.Dispose(); }
    }
}
'@
}

function Test-WindowsRuntimeRelativePath {
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

function Write-WindowsRuntimeFailure {
    param([string]$InputPath, [string]$OutputPath, [string]$Message)
    Remove-Item -LiteralPath (Join-Path $OutputPath 'observer-start.txt') -Force -ErrorAction SilentlyContinue
    $error = [ordered]@{
        schema_version = 1
        error = $Message
    }
    Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'guest-error.json') -Value $error
    $session = Read-WindowsRuntimeJson (Join-Path $InputPath 'session.json')
    $receipt = [ordered]@{
        schema_version = 1
        run_id = [string]$session.run_id
        attempt_id = [string]$session.attempt_id
        session_id = [string]$session.session_id
        status = 'ERROR'
    }
    Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'session.json') -Value $receipt
}

function Get-WindowsRuntimeInputParts {
    param($Inputs)
    $arguments = @($Inputs | Where-Object { $_.type -eq 'ARGUMENT' } |
        ForEach-Object { [string]$_.value })
    $stdin = ''
    $stdinInput = $Inputs | Where-Object { $_.type -eq 'STDIN' } | Select-Object -First 1
    if ($null -ne $stdinInput) { $stdin = [string]$stdinInput.value }
    $call = $Inputs | Where-Object { $_.type -eq 'PYTHON_CALL' } | Select-Object -First 1
    $invocation = [ordered]@{ args = $arguments; kwargs = [pscustomobject]@{}; stdin = $stdin }
    $invocationJson = if ($null -ne $call) {
        [string]$call.invocation_json
    } else {
        ConvertTo-Json -InputObject $invocation -Depth 100 -Compress
    }
    [pscustomobject]@{
        Arguments = $arguments; StandardInput = $stdin
        Invocation = $invocation; InvocationJson = $invocationJson
    }
}

function ConvertTo-WindowsArgument {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    # Windows doubles backslashes only before quotes and at a quoted argument's end.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Get-WindowsLibFuzzerCrashSignature {
    param([array]$Trials)

    foreach ($trial in @($Trials)) {
        $output = "{0}`n{1}" -f [string]$trial.stderr, [string]$trial.stdout
        $asan = [regex]::Match(
            $output,
            'ERROR:\s+(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer):\s+([A-Za-z0-9_-]+)'
        )
        if ($asan.Success) {
            return ('{0}:{1}' -f $asan.Groups[1].Value, $asan.Groups[2].Value)
        }
        $summary = [regex]::Match($output, 'SUMMARY:\s+\w+Sanitizer:\s+([A-Za-z0-9_-]+)')
        if ($summary.Success) {
            return $summary.Groups[1].Value
        }
    }
    return 'LLVM_LIBFUZZER_CRASH'
}

function Copy-WindowsRuntimeInputs {
    param([string]$InputPath, [string]$Work)
    # Resolve the root once and measure the offset against that same string. The
    # caller can hand us an 8.3 short path (GitHub's runner TEMP is
    # C:\Users\RUNNER~1\...) while Get-ChildItem reports FullName in the long
    # form, so subtracting the caller's length slices at the wrong offset and the
    # inputs land outside $Work. Do not reach for [IO.Path]::GetRelativePath:
    # powershell.exe runs on .NET Framework, which does not have it.
    $resolvedInput = (Get-Item -LiteralPath $InputPath).FullName
    Get-ChildItem -LiteralPath $resolvedInput -Recurse -File |
        Where-Object { $_.Name -notin @('session.json', 'runtime-config.json') } |
        ForEach-Object {
            $relative = $_.FullName.Substring($resolvedInput.Length + 1)
            $target = Join-Path $Work $relative
            $targetParent = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $targetParent)) {
                New-Item -ItemType Directory -Path $targetParent | Out-Null
            }
            Copy-Item -LiteralPath $_.FullName -Destination $target
        }
}

function Invoke-WindowsRuntimeTrial {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$StandardInput,
        [string]$Work,
        [int]$TimeoutSeconds,
        [string]$Label,
        [string]$Observer,
        [string]$MarkerPath
    )

    $marker = $null
    if ($Observer -eq 'FILE_CREATED' -and -not [string]::IsNullOrEmpty($MarkerPath)) {
        if (-not (Test-WindowsRuntimeRelativePath $MarkerPath)) {
            throw 'unsafe marker path'
        }
        $marker = Join-Path $Work $MarkerPath
        $markerParent = Split-Path -Parent $marker
        if (-not (Test-Path -LiteralPath $markerParent)) {
            New-Item -ItemType Directory -Path $markerParent | Out-Null
        }
        if (Test-Path -LiteralPath $marker) {
            Remove-Item -LiteralPath $marker -Force
        }
    }

    Initialize-WindowsRuntimeIO
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' '
    $startInfo.WorkingDirectory = $Work
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo

    $timedOut = $false
    $exception = ''
    $started = $false
    $stdoutCapture = $null
    $stderrCapture = $null
    $stdout = ''
    $stderr = ''
    $truncated = $false
    $exitCode = $null
    $reaped = $true
    $tasks = @()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $deadline = $TimeoutSeconds * 1000
    try {
        if (-not $process.Start()) { throw 'process did not start' }
        $started = $true
        $stdoutCapture = [AegisRuntimeCapture]::Start($process.StandardOutput.BaseStream, 256 * 1024)
        $stderrCapture = [AegisRuntimeCapture]::Start($process.StandardError.BaseStream, 256 * 1024)
        $stdinTask = [AegisRuntimeCapture]::WriteInput($process.StandardInput.BaseStream, $StandardInput)
        $tasks = [Threading.Tasks.Task[]]@($stdoutCapture.Completion, $stderrCapture.Completion, $stdinTask)
        $remaining = [int][Math]::Max(0, $deadline - $clock.ElapsedMilliseconds)
        $timedOut = -not $process.WaitForExit($remaining)
        if (-not $timedOut) {
            $remaining = [int][Math]::Max(0, $deadline - $clock.ElapsedMilliseconds)
            $timedOut = -not [Threading.Tasks.Task]::WaitAll($tasks, $remaining)
        }
    } catch {
        $exception = $_.Exception.Message
    } finally {
        if ($started) {
            if (-not $process.HasExited) {
                try { $process.Kill() } catch { $exception = $_.Exception.Message }
            }
            $reaped = $process.WaitForExit(2000)
            if ($tasks.Count -gt 0) {
                try { [void][Threading.Tasks.Task]::WaitAll($tasks, 500) } catch { }
            }
            $reaped = $reaped -and $null -ne $stdoutCapture -and $null -ne $stderrCapture `
                -and $stdoutCapture.Completion.IsCompleted -and $stderrCapture.Completion.IsCompleted
            if ($process.HasExited) { $exitCode = [int]$process.ExitCode }
            if ($null -ne $stdoutCapture) {
                $stdout = $stdoutCapture.Text
                $truncated = $stdoutCapture.Truncated
                if ($stdoutCapture.Error -and -not $exception) { $exception = $stdoutCapture.Error }
            }
            if ($null -ne $stderrCapture) {
                $stderr = $stderrCapture.Text
                $truncated = $truncated -or $stderrCapture.Truncated
                if ($stderrCapture.Error -and -not $exception) { $exception = $stderrCapture.Error }
            }
        }
        $process.Dispose()
    }
    if ($exception.Length -gt 4096) { $exception = $exception.Substring(0, 4096) }
    if ($timedOut -and [string]::IsNullOrEmpty($exception)) { $exception = 'TIMEOUT' }
    $signature = if ($timedOut) { 'TIMEOUT' } elseif ($null -ne $exitCode -and $exitCode -ne 0) { "EXIT_$exitCode" } else { '' }
    $observed = $false
    if ($Observer -eq 'FILE_CREATED' -and -not $timedOut -and -not $exception) {
        $observed = $null -ne $marker -and (Test-Path -LiteralPath $marker -PathType Leaf)
    } elseif ($Observer -eq 'SANITIZER' -and -not $timedOut -and -not $exception -and $null -ne $exitCode) {
        $status = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exitCode), 0)
        $statusHex = '{0:X8}' -f $status
        # This runner does not enable sanitizer instrumentation. Logs alone are not crash evidence.
        if ($statusHex -in @('C0000005', 'C000001D', 'C00000FD', 'C0000374', 'C0000409')) {
            $observed = $true
            $signature = "NTSTATUS_$statusHex"
        }
    }

    [ordered]@{
        label = $Label
        exit_code = $exitCode
        timed_out = $timedOut
        processes_reaped = $reaped
        observed = $observed
        exception = $exception
        stdout = $stdout
        stderr = $stderr
        truncated = $truncated
        crash_signature = $signature
    }
}

function Invoke-WindowsRuntimeTrials {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$PythonPath,
        [string]$ZigPath,
        [Parameter(Mandatory = $true)][ValidateSet('ORIGINAL_PE', 'WINDOWS_PYTHON', 'WINDOWS_NATIVE_SOURCE')][string]$Kind
    )

    $ErrorActionPreference = 'Stop'
    $ProjectRoot = (Get-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).FullName
    if ([string]::IsNullOrEmpty($PythonPath)) {
        $PythonPath = Join-Path $ProjectRoot '.tools\windows-python'
    }
    if ([string]::IsNullOrEmpty($ZigPath)) {
        $ZigPath = Join-Path $ProjectRoot '.tools\zig'
    }

    Set-Content -LiteralPath (Join-Path $OutputPath 'observer-start.txt') -Value 'started' -Encoding ASCII

    try {
        $session = Read-WindowsRuntimeJson (Join-Path $InputPath 'session.json')
        $config = Read-WindowsRuntimeJson (Join-Path $InputPath 'runtime-config.json')
        if ($session.schema_version -ne 1 -or $config.schema_version -ne 1) {
            throw 'unsupported host runtime schema'
        }
        if ($config.mode -ne 'VERIFY') {
            throw 'the Windows product runtime currently supports VERIFY mode'
        }
        if (-not (Test-WindowsRuntimeRelativePath $config.target_path)) {
            throw 'unsafe target path'
        }

        $compileExitCode = $null
        $compiler = ''
        $compileStdoutPath = Join-Path $OutputPath 'compile.stdout.log'
        $compileStderrPath = Join-Path $OutputPath 'compile.stderr.log'
        $runtimeRoot = Join-Path ([IO.Path]::GetTempPath()) 'AegisAuditRuntime'
        if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
            New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
        }
        $sharedWork = Join-Path $runtimeRoot ('runtime-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $sharedWork | Out-Null

        if ($Kind -eq 'WINDOWS_NATIVE_SOURCE') {
            if ($config.adapter -ne 'WINDOWS_NATIVE_SOURCE') { throw 'adapter mismatch' }
            $zig = Join-Path $ZigPath 'zig.exe'
            if (-not (Test-Path -LiteralPath $zig -PathType Leaf)) { throw 'Zig runtime is missing' }
            $compiler = (& $zig version) -join ''
            $mode = if ($config.target_path -match '\.c$') { 'cc' } else { 'c++' }
            $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $sharedWork 'global-cache'
            $env:ZIG_LOCAL_CACHE_DIR = Join-Path $sharedWork 'local-cache'
            New-Item -ItemType Directory -Path $env:ZIG_GLOBAL_CACHE_DIR, $env:ZIG_LOCAL_CACHE_DIR | Out-Null
            New-Item -ItemType File -Path $compileStdoutPath, $compileStderrPath -Force | Out-Null
            $compiled = Join-Path $sharedWork 'target.exe'
            $targetSource = Join-Path $InputPath $config.target_path
            $compileStdout = & $zig $mode -O0 $targetSource -o $compiled 2> $compileStderrPath
            Set-Content -LiteralPath $compileStdoutPath -Value ([string]::Join("`n", @($compileStdout))) -Encoding ASCII
            $compileExitCode = $LASTEXITCODE
            if ($compileExitCode -ne 0 -or -not (Test-Path -LiteralPath $compiled -PathType Leaf)) {
                throw "native-source compile failed with exit code $compileExitCode"
            }
        }

        $observer = if ($config.environment.observer) { [string]$config.environment.observer } else { 'SANITIZER' }
        $markerPath = if ($config.environment.marker_path) { [string]$config.environment.marker_path } else { '' }
        $plans = @(@{ Label = 'baseline'; Inputs = $config.baseline_inputs })
        for ($index = 0; $index -lt [int]$config.repeats; $index++) {
            $plans += @{ Label = 'probe'; Inputs = $config.probe_inputs }
        }
        $trials = @()
        foreach ($plan in $plans) {
            $work = Join-Path $sharedWork ([string]$plan.Label + '-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $work | Out-Null
            Copy-WindowsRuntimeInputs -InputPath $InputPath -Work $work
            $parts = Get-WindowsRuntimeInputParts -Inputs $plan.Inputs

            if ($Kind -eq 'ORIGINAL_PE') {
                if ($config.adapter -notin @('WINDOWS_ORIGINAL_PE32', 'WINDOWS_ORIGINAL_PE64')) { throw 'adapter mismatch' }
                $target = Join-Path $work $config.target_path
                if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'target is missing' }
                $arguments = @($config.entry.arguments) + @($parts.Arguments)
                $parts.Invocation.args = $arguments
                $parts.InvocationJson = ConvertTo-Json -InputObject $parts.Invocation -Depth 100 -Compress
                $trial = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $arguments `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            } elseif ($Kind -eq 'WINDOWS_PYTHON') {
                if ($config.adapter -ne 'WINDOWS_PYTHON_CALL') { throw 'adapter mismatch' }
                $python = Join-Path $PythonPath 'python.exe'
                if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Python runtime is missing: $python" }
                $module = Join-Path $work $config.entry.module
                if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw 'Python module is missing' }
                $globalsJson = if ($config.environment.globals_json) { [string]$config.environment.globals_json } else { '{}' }
                $payload = [ordered]@{
                    module = $module; function = $config.entry.function
                    invocation_json = $parts.InvocationJson; globals_json = $globalsJson
                }
                $payloadJson = ConvertTo-Json -InputObject $payload -Depth 100 -Compress
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payloadJson))
                $code = @"
import base64, importlib.util, json, sys
from pathlib import Path
payload = json.loads(base64.b64decode('$encoded').decode('utf-8'))
sys.path.insert(0, str(Path(__file__).parent))
spec = importlib.util.spec_from_file_location('aegis_target', payload['module'])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for name, value in json.loads(payload['globals_json']).items():
    setattr(module, name, value)
call = json.loads(payload['invocation_json'])
print(getattr(module, payload['function'])(*call['args'], **call['kwargs']))
"@
                $wrapper = Join-Path $work 'aegis-python-wrapper.py'
                Set-Content -LiteralPath $wrapper -Value $code -Encoding UTF8
                $trial = Invoke-WindowsRuntimeTrial -FilePath $python -Arguments @('-I', '-X', 'utf8', $wrapper) `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            } else {
                $target = Join-Path $sharedWork 'target.exe'
                $arguments = @($config.entry.arguments) + @($parts.Arguments)
                $parts.Invocation.args = $arguments
                $parts.InvocationJson = ConvertTo-Json -InputObject $parts.Invocation -Depth 100 -Compress
                $trial = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $arguments `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            }
            $trial.input_json = $parts.InvocationJson
            $trials += $trial
            if (-not $trial.processes_reaped) { throw 'trial I/O remained active; stopping before another trial' }
        }

        $first = $trials | Select-Object -First 1
        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stdout.log') -Value $first.stdout -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stderr.log') -Value $first.stderr -Encoding UTF8
        $observation = [ordered]@{
            schema_version = 1
            session_id = [string]$session.session_id
            adapter = [string]$config.adapter
            target_path = [string]$config.target_path
            function = [string]$config.entry.function
            entry = if ($Kind -eq 'WINDOWS_PYTHON') { 'FUNCTION' } else { 'COMMAND_LINE' }
            compiler = if ($compiler) { "zig $compiler" } else { '' }
            compile_exit_code = $compileExitCode
            exit_code = $first.exit_code
            trials = $trials
            stdout_file = 'target.stdout.log'
            stderr_file = 'target.stderr.log'
        }
        Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'guest-observation.json') -Value $observation
        Set-Content -LiteralPath (Join-Path $OutputPath 'target-executed.txt') `
            -Value "session=$($session.session_id);trials=$($trials.Count)" -Encoding ASCII

        $receipt = [ordered]@{
            schema_version = 1
            run_id = [string]$session.run_id
            attempt_id = [string]$session.attempt_id
            session_id = [string]$session.session_id
            status = 'COMPLETED'
        }
        Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'session.json') -Value $receipt
        Remove-Item -LiteralPath (Join-Path $OutputPath 'observer-start.txt') -Force -ErrorAction SilentlyContinue
    } catch {
        Write-WindowsRuntimeFailure -InputPath $InputPath -OutputPath $OutputPath -Message $_.Exception.Message
    }
}

function Invoke-WindowsLibFuzzerTrials {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$LlvmPath
    )

    $ErrorActionPreference = 'Stop'
    $ProjectRoot = (Get-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).FullName
    if ([string]::IsNullOrEmpty($LlvmPath)) {
        $LlvmPath = Join-Path $ProjectRoot '.tools\llvm-min'
    }

    Set-Content -LiteralPath (Join-Path $OutputPath 'observer-start.txt') -Value 'started' -Encoding ASCII

    try {
        $session = Read-WindowsRuntimeJson (Join-Path $InputPath 'session.json')
        $config = Read-WindowsRuntimeJson (Join-Path $InputPath 'runtime-config.json')
        if ($session.schema_version -ne 1 -or $config.schema_version -ne 1) {
            throw 'unsupported host runtime schema'
        }
        if ($config.mode -ne 'FUZZ' -or $config.adapter -ne 'WINDOWS_LIBFUZZER_PREBUILT') {
            throw 'the libFuzzer runner only supports FUZZ mode with a prebuilt target'
        }
        if (-not (Test-WindowsRuntimeRelativePath $config.target_path)) {
            throw 'unsafe target path'
        }

        $runtimeRoot = Join-Path ([IO.Path]::GetTempPath()) 'AegisAuditRuntime'
        if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
            New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
        }
        $work = Join-Path $runtimeRoot ('libfuzzer-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $work | Out-Null
        Copy-WindowsRuntimeInputs -InputPath $InputPath -Work $work

        $target = Join-Path $work $config.target_path
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            throw 'libFuzzer target is missing'
        }

        $corpus = Join-Path $work 'corpus'
        New-Item -ItemType Directory -Path $corpus | Out-Null
        for ($index = 0; $index -lt $config.fuzz.seeds.Count; $index++) {
            $seedPath = Join-Path $corpus ("seed-{0:d3}" -f $index)
            [IO.File]::WriteAllBytes($seedPath, [Text.Encoding]::UTF8.GetBytes([string]$config.fuzz.seeds[$index]))
        }

        $artifactPrefix = Join-Path $work ''
        $arguments = @($config.entry.arguments) + @(
            "-runs=$([int]$config.fuzz.runs)",
            "-max_len=$([int]$config.fuzz.max_input_bytes)",
            "-timeout=$([int]$config.fuzz.timeout_seconds)",
            "-seed=$([int64]$config.fuzz.random_seed)",
            "-artifact_prefix=$artifactPrefix",
            $corpus
        )

        $runtimeLibrary = Join-Path $LlvmPath 'lib\clang\23\lib\windows'
        if (Test-Path -LiteralPath $runtimeLibrary -PathType Container) {
            $env:PATH = "$runtimeLibrary;$env:PATH"
        }

        $trial = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $arguments `
            -StandardInput '' -Work $work -TimeoutSeconds ([int]$config.fuzz.budget_seconds) `
            -Label 'fuzz' -Observer 'SANITIZER' -MarkerPath ''

        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stdout.log') -Value $trial.stdout -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stderr.log') -Value $trial.stderr -Encoding UTF8

        $crashes = @()
        $artifactFiles = @()
        if ($null -ne $trial.exit_code -and $trial.exit_code -ne 0) {
            $artifactFiles = @(Get-ChildItem -LiteralPath $work -Filter 'crash-*' -File |
                Sort-Object @{ Expression = 'Length'; Descending = $false },
                    @{ Expression = 'LastWriteTime'; Descending = $true } |
                Select-Object -First 16)
        }

        $representatives = @{}
        $representativeOrder = @()
        foreach ($artifactFile in $artifactFiles) {
            $artifact = $artifactFile.FullName
            $classification = Invoke-WindowsRuntimeTrial -FilePath $target `
                -Arguments (@($config.entry.arguments) + @($artifact)) `
                -StandardInput '' -Work $work -TimeoutSeconds ([int]$config.fuzz.timeout_seconds) `
                -Label 'classify' -Observer 'SANITIZER' -MarkerPath ''
            $classification.observed = $null -ne $classification.exit_code -and
                $classification.exit_code -ne 0 -and -not $classification.timed_out
            if (-not $classification.observed) { continue }
            $signature = Get-WindowsLibFuzzerCrashSignature @($classification)
            if (-not $representatives.ContainsKey($signature)) {
                $representatives[$signature] = $artifactFile
                $representativeOrder += $signature
            }
        }

        $crashIndex = 0
        foreach ($signature in $representativeOrder) {
            $crashIndex++
            $artifact = $representatives[$signature].FullName
            $artifactName = 'crash-{0:d2}-input.bin' -f $crashIndex
            $finalArtifact = $artifact
            $minimizedArtifact = Join-Path $work ('minimized-' + [guid]::NewGuid().ToString('N') + '.bin')

            $minimizeArguments = @($config.entry.arguments) + @(
                '-minimize_crash=1',
                "-exact_artifact_path=$minimizedArtifact",
                "-timeout=$([int]$config.fuzz.timeout_seconds)",
                "-max_total_time=$([int][Math]::Min([int]$config.fuzz.budget_seconds, 60))",
                $artifact
            )
            $minimization = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $minimizeArguments `
                -StandardInput '' -Work $work -TimeoutSeconds ([int]$config.fuzz.budget_seconds + 90) `
                -Label 'minimize' -Observer 'SANITIZER' -MarkerPath ''
            Set-Content -LiteralPath (Join-Path $OutputPath ('crash-{0:d2}-minimize.stdout.log' -f $crashIndex)) `
                -Value $minimization.stdout -Encoding UTF8
            Set-Content -LiteralPath (Join-Path $OutputPath ('crash-{0:d2}-minimize.stderr.log' -f $crashIndex)) `
                -Value $minimization.stderr -Encoding UTF8
            if ($null -ne $minimization.exit_code -and $minimization.exit_code -eq 0 -and
                (Test-Path -LiteralPath $minimizedArtifact -PathType Leaf)) {
                $finalArtifact = $minimizedArtifact
            }

            Copy-Item -LiteralPath $finalArtifact -Destination (Join-Path $OutputPath $artifactName)
            $bytes = [IO.File]::ReadAllBytes($finalArtifact)
            $inputHex = [BitConverter]::ToString($bytes).Replace('-', '')
            $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
            $inputHash = [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
            $replays = @()
            for ($index = 1; $index -le 2; $index++) {
                $replayArguments = @($config.entry.arguments) + @($finalArtifact)
                $replay = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $replayArguments `
                    -StandardInput '' -Work $work -TimeoutSeconds ([int]$config.fuzz.timeout_seconds) `
                    -Label 'replay' -Observer 'SANITIZER' -MarkerPath ''
                $replay.observed = $null -ne $replay.exit_code -and $replay.exit_code -ne 0
                $replay.crash_signature = $signature
                $replay.input_sha256 = $inputHash
                $replays += $replay
            }
            $badReplays = @($replays | Where-Object {
                -not $_.processes_reaped -or $_.timed_out -or $_.truncated -or
                -not $_.observed -or $_.crash_signature -ne $signature
            })
            $crashes += [ordered]@{
                input_hex = $inputHex
                input_sha256 = $inputHash
                signature = $signature
                reproduced = $badReplays.Count -eq 0
                minimized = $finalArtifact -eq $minimizedArtifact
                replays = $replays
            }
        }

        $observation = [ordered]@{
            schema_version = 1
            session_id = [string]$session.session_id
            mode = 'FUZZ'
            adapter = [string]$config.adapter
            target_path = [string]$config.target_path
            build = [ordered]@{
                status = if ($trial.exception -or -not $trial.processes_reaped) { 'ERROR' } else { 'READY' }
                engine = 'LLVM libFuzzer'
                instrumentation = 'coverage-guided'
            }
            trials = @()
            fuzz = [ordered]@{
                engine = 'LLVM_LIBFUZZER'
                executions = [int]$config.fuzz.runs
                coverage_feedback = $true
                timeouts = if ($trial.timed_out) { 1 } else { 0 }
                runs = [int]$config.fuzz.runs
                max_input_bytes = [int]$config.fuzz.max_input_bytes
                timeout_seconds = [int]$config.fuzz.timeout_seconds
                budget_seconds = [int]$config.fuzz.budget_seconds
                random_seed = [int64]$config.fuzz.random_seed
            }
            crashes = $crashes
            error = [string]$trial.exception
        }
        Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'guest-observation.json') -Value $observation
        Set-Content -LiteralPath (Join-Path $OutputPath 'target-executed.txt') `
            -Value "session=$($session.session_id);runs=$($config.fuzz.runs)" -Encoding ASCII

        $receipt = [ordered]@{
            schema_version = 1
            run_id = [string]$session.run_id
            attempt_id = [string]$session.attempt_id
            session_id = [string]$session.session_id
            status = 'COMPLETED'
        }
        Write-WindowsRuntimeJson -Path (Join-Path $OutputPath 'session.json') -Value $receipt
        Remove-Item -LiteralPath (Join-Path $OutputPath 'observer-start.txt') -Force -ErrorAction SilentlyContinue
    } catch {
        Write-WindowsRuntimeFailure -InputPath $InputPath -OutputPath $OutputPath -Message $_.Exception.Message
    }
}

# Wrappers dot-source this library and invoke the function themselves.
if ($MyInvocation.InvocationName -ne '.') {
    if ($Kind -eq 'WINDOWS_LIBFUZZER') {
        Invoke-WindowsLibFuzzerTrials -InputPath $InputPath -OutputPath $OutputPath -LlvmPath $LlvmPath
    } else {
        Invoke-WindowsRuntimeTrials -InputPath $InputPath -OutputPath $OutputPath -PythonPath $PythonPath -ZigPath $ZigPath -Kind $Kind
    }
}
