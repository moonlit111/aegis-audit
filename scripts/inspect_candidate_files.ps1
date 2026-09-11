#requires -Version 7.0
<#
Read PE metadata and test UPX integrity without executing or modifying targets.
Neither a version resource nor UPX detection establishes software acceptance.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Path,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$Upx = "$PSScriptRoot/../.tools/reverse/upx/upx-5.2.1-win64/upx.exe"
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath("$PSScriptRoot/..")
$upxPath = (Resolve-Path -LiteralPath $Upx).Path
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'Evidence already exists; choose a new output path.' }
$results = foreach ($candidate in $Path) {
    $file = Get-Item -LiteralPath $candidate
    $result = [ordered]@{
        path = [IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
        bytes = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        target_executed = $false
        target_modified = $false
        formal_acceptance = $false
        provenance_verified = $false
        code_obfuscation = 'NOT_ESTABLISHED'
    }
    $stream = $null
    $pe = $null
    try {
        $stream = [IO.File]::OpenRead($file.FullName)
        $pe = [System.Reflection.PortableExecutable.PEReader]::new($stream)
        $headers = $pe.PEHeaders
        if (-not $headers.PEHeader) { throw 'Input does not contain a PE optional header.' }
        $result.pe = [ordered]@{
            machine = $headers.CoffHeader.Machine.ToString()
            image_base = ('0x{0:X}' -f $headers.PEHeader.ImageBase)
            entry_point_rva = ('0x{0:X}' -f $headers.PEHeader.AddressOfEntryPoint)
            has_managed_metadata = $pe.HasMetadata
            sections = @($headers.SectionHeaders | ForEach-Object {
                [ordered]@{ name = $_.Name; rva = $_.VirtualAddress; virtual_bytes = $_.VirtualSize;
                    file_offset = $_.PointerToRawData; raw_bytes = $_.SizeOfRawData }
            })
        }
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
        $result.version_resource = [ordered]@{
            product = $version.ProductName
            description = $version.FileDescription
            file_version = $version.FileVersion
            product_version = $version.ProductVersion
            original_filename = $version.OriginalFilename
            company = $version.CompanyName
        }
    } catch {
        $result.pe_error = $_.Exception.Message
    } finally {
        if ($pe) { $pe.Dispose() }
        if ($stream) { $stream.Dispose() }
    }

    $info = [Diagnostics.ProcessStartInfo]::new($upxPath)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.ArgumentList.Add('-t')
    $info.ArgumentList.Add('--')
    $info.ArgumentList.Add($file.FullName)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit(30000)
        if ($timedOut) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        $result.upx_test = [ordered]@{
            command = @($upxPath, '-t', '--', $file.FullName)
            exit_code = $process.ExitCode
            timed_out = $timedOut
            stdout = $out
            stderr = $err
        }
        $result.packing = if ($timedOut) { 'UNKNOWN' }
            elseif ($process.ExitCode -eq 0) { 'UPX_CONFIRMED' }
            elseif (($out + $err).Contains('NotPackedException')) { 'UPX_NOT_DETECTED' }
            else { 'UNKNOWN' }
    } finally {
        $process.Dispose()
    }
    $after = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($after -ne $result.sha256) { throw "Candidate changed while inspecting: $candidate" }
    [pscustomobject]$result
}
$document = [ordered]@{
    schema_version = 1
    checked_at = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'READ_ONLY_PE_AND_UPX_QUALIFICATION'
    tool = [ordered]@{ path = $upxPath; sha256 = (Get-FileHash -LiteralPath $upxPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    formal_acceptance = $false
    limitations = @('UPX_NOT_DETECTED does not rule out other packers.',
        'Version resources are not verified provenance or proof of vulnerability.',
        'Code obfuscation, license scope, normal execution and vulnerability validation remain separate requirements.')
    results = @($results)
}
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputPath))
$document | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $outputPath -Encoding utf8
$results | Select-Object path, packing, @{Name = 'product'; Expression = { $_.version_resource.product }},
    @{Name = 'version'; Expression = { $_.version_resource.file_version }} | ConvertTo-Json
