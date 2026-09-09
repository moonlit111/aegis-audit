param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

. (Join-Path $PSScriptRoot 'run-windows-trials.ps1')
Invoke-WindowsRuntimeTrials -InputPath $InputPath -OutputPath $OutputPath -Kind WINDOWS_PYTHON
