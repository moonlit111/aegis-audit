param(
    [string]$InputPath,
    [string]$OutputPath,
    [string]$PythonPath,
    [string]$ZigPath,
    [ValidateSet('ORIGINAL_PE', 'WINDOWS_PYTHON', 'WINDOWS_NATIVE_SOURCE')]
    [string]$Kind
)


function Read-WindowsRuntimeJson {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-WindowsRuntimeJson {
    param([string]$Path, [object]$Value)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Value -Depth 8), $encoding)
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
    [pscustomobject]@{ Arguments = $arguments; StandardInput = $stdin }
}

function ConvertTo-WindowsArgument {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function Copy-WindowsRuntimeInputs {
    param([string]$InputPath, [string]$Work)
    Get-ChildItem -LiteralPath $InputPath -Recurse -File |
        Where-Object { $_.Name -notin @('session.json', 'runtime-config.json') } |
        ForEach-Object {
            $relative = $_.FullName.Substring($InputPath.Length + 1)
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

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' '
    $startInfo.WorkingDirectory = $Work
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo

    $timedOut = $false
    $exception = ''
    try {
        if (-not $process.Start()) { throw 'process did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not [string]::IsNullOrEmpty($StandardInput)) {
            $process.StandardInput.Write($StandardInput)
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            $process.Kill()
            $process.WaitForExit()
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
    } catch {
        $exception = $_.Exception.Message
        $stdout = ''
        $stderr = ''
        if (-not $process.HasExited) {
            try { $process.Kill(); $process.WaitForExit() } catch { }
        }
    }

    $limit = 256 * 1024
    $truncated = $stdout.Length -gt $limit -or $stderr.Length -gt $limit
    if ($stdout.Length -gt $limit) { $stdout = $stdout.Substring(0, $limit) }
    if ($stderr.Length -gt $limit) { $stderr = $stderr.Substring(0, $limit) }

    $observed = $false
    if ($Observer -eq 'FILE_CREATED') {
        $observed = $null -ne $marker -and (Test-Path -LiteralPath $marker -PathType Leaf)
    } elseif ($Observer -eq 'SANITIZER') {
        $observed = $stderr -match 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault'
    }

    $exitCode = $null
    if ($process.HasExited) { $exitCode = [int]$process.ExitCode }
    if ($timedOut -and [string]::IsNullOrEmpty($exception)) { $exception = 'TIMEOUT' }
    $signature = if ($timedOut) { 'TIMEOUT' } elseif ($null -ne $exitCode -and $exitCode -ne 0) { "EXIT_$exitCode" } else { '' }

    [ordered]@{
        label = $Label
        exit_code = $exitCode
        timed_out = $timedOut
        processes_reaped = $process.HasExited
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
                $trial = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $parts.Arguments `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            } elseif ($Kind -eq 'WINDOWS_PYTHON') {
                if ($config.adapter -ne 'WINDOWS_PYTHON_CALL') { throw 'adapter mismatch' }
                $python = Join-Path $PythonPath 'python.exe'
                if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Python runtime is missing: $python" }
                $module = Join-Path $work $config.entry.module
                if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw 'Python module is missing' }
                $argumentJson = ConvertTo-Json @($parts.Arguments) -Compress
                $moduleJson = ConvertTo-Json $module -Compress
                $functionJson = ConvertTo-Json $config.entry.function -Compress
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argumentJson))
                $code = @"
import base64, importlib.util, json
arguments = json.loads(base64.b64decode('$encoded').decode('utf-8'))
spec = importlib.util.spec_from_file_location('aegis_target', $moduleJson)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(getattr(module, $functionJson)(*arguments))
"@
                $wrapper = Join-Path $work 'aegis-python-wrapper.py'
                Set-Content -LiteralPath $wrapper -Value $code -Encoding UTF8
                $trial = Invoke-WindowsRuntimeTrial -FilePath $python -Arguments @('-I', $wrapper) `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            } else {
                $target = Join-Path $sharedWork 'target.exe'
                $trial = Invoke-WindowsRuntimeTrial -FilePath $target -Arguments $parts.Arguments `
                    -StandardInput $parts.StandardInput -Work $work -TimeoutSeconds $config.timeout_seconds `
                    -Label $plan.Label -Observer $observer -MarkerPath $markerPath
            }
            $trials += $trial
        }

        $first = $trials | Select-Object -First 1
        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stdout.log') -Value $first.stdout -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $OutputPath 'target.stderr.log') -Value $first.stderr -Encoding ASCII
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

# Wrappers dot-source this library and invoke the function themselves.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WindowsRuntimeTrials -InputPath $InputPath -OutputPath $OutputPath -PythonPath $PythonPath -ZigPath $ZigPath -Kind $Kind
}
