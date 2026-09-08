param([string]$OutputPath = "")

# Read-only environment inspection. This script does not install tools or enable features.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $ProjectRoot (".data\windows\preflight-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
}

function Get-AegisTool([string]$Name, [string[]]$ToolArgs) {
    $Executable = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Executable) { return @{ available = $false; detail = "Not found in PATH" } }
    try {
        $ErrorActionPreference = "Continue"
        $ToolOutput = (& $Executable.Source @ToolArgs 2>&1 | Out-String).Trim()
        return @{ available = $true; path = $Executable.Source; exit_code = $LASTEXITCODE; detail = $ToolOutput }
    } catch {
        return @{ available = $true; path = $Executable.Source; error = $_.Exception.Message }
    }
}

$OperatingSystem = Get-CimInstance Win32_OperatingSystem
$Computer = Get-CimInstance Win32_ComputerSystem
$Processors = @(Get-CimInstance Win32_Processor | Select-Object Name, AddressWidth, NumberOfCores, NumberOfLogicalProcessors, VirtualizationFirmwareEnabled)
$ToolVersions = [ordered]@{}
foreach ($Tool in @("git", "rustc", "cargo", "cmake", "python", "node", "pnpm")) {
    $ToolVersions[$Tool] = Get-AegisTool $Tool @("--version")
}
$ToolVersions["java"] = Get-AegisTool "java" @("-version")
$ToolVersions["python_launcher"] = Get-AegisTool "py.exe" @("-3", "--version")
$ToolVersions["docker"] = Get-AegisTool "docker" @("version")
$ToolVersions["wsl"] = Get-AegisTool "wsl.exe" @("--status")
$ToolVersions["wsl_distributions"] = Get-AegisTool "wsl.exe" @("--list", "--verbose")
$VisualStudioLocator = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $VisualStudioLocator) {
    $VisualStudioCpp = Get-AegisTool $VisualStudioLocator @("-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath")
    $VisualStudioCpp["available"] = $VisualStudioCpp.exit_code -eq 0 -and -not [string]::IsNullOrWhiteSpace($VisualStudioCpp.detail)
    $ToolVersions["visual_studio_cpp"] = $VisualStudioCpp
} else { $ToolVersions["visual_studio_cpp"] = @{ available = $false } }
$WindowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include"
$WindowsSdkVersions = if (Test-Path $WindowsSdkRoot) {
    @(Get-ChildItem $WindowsSdkRoot -Directory | Where-Object { Test-Path (Join-Path $_.FullName "um\Windows.h") } | Select-Object -ExpandProperty Name)
} else { @() }
$ToolVersions["windows_sdk"] = @{ available = @($WindowsSdkVersions).Count -gt 0; include_root = $WindowsSdkRoot; versions = @($WindowsSdkVersions) }

$Features = [ordered]@{}
foreach ($Feature in @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Containers-DisposableClientVM", "Microsoft-Hyper-V-All")) {
    try { $Features[$Feature] = (Get-WindowsOptionalFeature -Online -FeatureName $Feature).State.ToString() }
    catch { $Features[$Feature] = "Unknown: " + $_.Exception.Message }
}
$Report = [ordered]@{
    schema_version = 1
    inspected_at = (Get-Date).ToUniversalTime().ToString("o")
    powershell = $PSVersionTable.PSVersion.ToString()
    windows = @{ caption = $OperatingSystem.Caption; version = $OperatingSystem.Version; build = $OperatingSystem.BuildNumber; architecture = $OperatingSystem.OSArchitecture }
    memory_gib = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)
    hypervisor_present = $Computer.HypervisorPresent
    processors = $Processors
    disks = @(Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{ Name = "free_gib"; Expression = { [math]::Round($_.Free / 1GB, 2) } })
    optional_features = $Features
    tools = $ToolVersions
}
$ReportDirectory = Split-Path -Parent $OutputPath
if ($ReportDirectory) { New-Item -ItemType Directory -Force $ReportDirectory | Out-Null }
$Report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output ("Environment report: " + $OutputPath)
