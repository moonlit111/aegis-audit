param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$PythonPath,
    [string]$ZigPath,
    [string]$LlvmPath
)

& (Join-Path $PSScriptRoot 'run-windows-trials.ps1') `
    -InputPath $InputPath `
    -OutputPath $OutputPath `
    -PythonPath $PythonPath `
    -ZigPath $ZigPath `
    -LlvmPath $LlvmPath `
    -Kind WINDOWS_LIBFUZZER
