param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$PythonPath,
    [string]$ZigPath
)

& (Join-Path $PSScriptRoot 'run-windows-trials.ps1') -InputPath $InputPath -OutputPath $OutputPath -PythonPath $PythonPath -ZigPath $ZigPath -Kind WINDOWS_NATIVE_SOURCE
