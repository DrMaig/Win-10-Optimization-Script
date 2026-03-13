<#
.SYNOPSIS
Optimize-Windows10.ps1 performs safe, reversible Windows 10 optimization in ordered modules.

.DESCRIPTION
This script is generated in module-by-module chunks. It enforces strict safety gates, logs in UTC,
and preserves sensitive user data. System validation (DISM/SFC) is reserved for script closure and
must run last after all cleanup and optimization modules.

.PARAMETER DryRun
Lists planned actions and performs no system changes. Takes precedence over all action switches.

.PARAMETER AutoApprove
Skips interactive confirmations. Does not skip backups or restore point requirements.

.PARAMETER Force
Suppresses non-critical warnings only. Does not bypass mandatory safety rules.

.PARAMETER RemoveDuplicateDrivers
Enables duplicate driver removal flow (disabled by default).

.PARAMETER PreviewDriversToRemove
Shows driver deduplication preview only. Performs no changes.

.PARAMETER IgnoreOSCheck
Skips OS build validation and logs a warning.

.PARAMETER SkipRestorePoint
Skips restore point creation and logs a warning.

.PARAMETER LogPath
Directory for UTC log output.

.PARAMETER BackupPath
Directory for backup artifacts.

.PARAMETER CleanupAgeDays
Age threshold for orphaned temporary file cleanup.

.PARAMETER VisualEffectsPreset
Visual effects preset: Balanced, Performance, or MaxPerformance.

.EXAMPLE
.\Optimize-Windows10.ps1 -DryRun -Verbose
#>

# Changelog
# 2026-03-13  Initial generated baseline (Phase 2, Modules 1-4)
#
# Author: GitHub Copilot (GPT-5.3-Codex)
# Version: 1.0.0
# Requires: Windows PowerShell 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
	[switch]$DryRun,
	[switch]$AutoApprove,
	[switch]$Force,
	[switch]$RemoveDuplicateDrivers,
	[switch]$PreviewDriversToRemove,
	[switch]$IgnoreOSCheck,
	[switch]$SkipRestorePoint,
	[string]$LogPath = 'C:\ProgramData\OptimizeWindows\Logs\',
	[string]$BackupPath = 'C:\ProgramData\OptimizeWindows\Backups\',
	[ValidateRange(1, 3650)]
	[int]$CleanupAgeDays = 7,
	[ValidateSet('Balanced', 'Performance', 'MaxPerformance')]
	[string]$VisualEffectsPreset = 'Balanced'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Core Utilities

function New-ModuleResult {
<#
.SYNOPSIS
Creates a standardized module result object.

.DESCRIPTION
Returns a structured object with a consistent schema for module reporting and aggregation.

.PARAMETER ModuleName
Logical module name.

.EXAMPLE
$result = New-ModuleResult -ModuleName 'Module1'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$ModuleName
	)

	[pscustomobject]@{
		ModuleName     = $ModuleName
		Success        = $true
		ChangesApplied = @()
		Warnings       = @()
		Errors         = @()
		RollbackSteps  = @()
		StartedUtc     = (Get-Date).ToUniversalTime().ToString('o')
		EndedUtc       = $null
	}
}

function Write-LogUtc {
<#
.SYNOPSIS
Writes a UTC timestamped log entry.

.DESCRIPTION
Appends a single UTF-8 log line with UTC timestamp and level to the active script log file.
Logging is non-optional and used by all modules.

.PARAMETER Message
Log message content.

.PARAMETER Level
Log level label (INFO, WARN, ERROR).

.EXAMPLE
Write-LogUtc -Message 'Hardware profile collected.' -Level 'INFO'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,

		[ValidateSet('INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO'
	)

	if (-not $script:LogFilePath) {
		throw 'Log file path is not initialized. Call Initialize-ExecutionContext first.'
	}

	$utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
	$line = '{0} [{1}] {2}' -f $utc, $Level, $Message
	Add-Content -Path $script:LogFilePath -Value $line -Encoding UTF8
}

function Initialize-ExecutionContext {
<#
.SYNOPSIS
Initializes runtime folders, log file, and banner warnings.

.DESCRIPTION
Creates required directories (if missing), initializes log file path, and emits startup warning
banners for operational modes such as AutoApprove and DryRun.

.PARAMETER LogPath
Log directory path.

.PARAMETER BackupPath
Backup directory path.

.EXAMPLE
Initialize-ExecutionContext -LogPath $LogPath -BackupPath $BackupPath
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$LogPath,

		[Parameter(Mandatory = $true)]
		[string]$BackupPath
	)

	$script:ExecutionStartUtc = (Get-Date).ToUniversalTime()
	$script:RunId = $script:ExecutionStartUtc.ToString('yyyyMMddTHHmmssZ')
	$script:ResolvedLogPath = [System.IO.Path]::GetFullPath($LogPath)
	$script:ResolvedBackupPath = [System.IO.Path]::GetFullPath($BackupPath)

	if (-not (Test-Path -Path $script:ResolvedLogPath -PathType Container)) {
		New-Item -Path $script:ResolvedLogPath -ItemType Directory -Force | Out-Null
	}
	if (-not (Test-Path -Path $script:ResolvedBackupPath -PathType Container)) {
		New-Item -Path $script:ResolvedBackupPath -ItemType Directory -Force | Out-Null
	}

	$script:LogFilePath = Join-Path -Path $script:ResolvedLogPath -ChildPath ("Optimize-Windows10_{0}.log" -f $script:RunId)
	New-Item -Path $script:LogFilePath -ItemType File -Force | Out-Null

	Write-LogUtc -Message ('RunId={0}; DryRun={1}; AutoApprove={2}; Force={3}' -f $script:RunId, $DryRun.IsPresent, $AutoApprove.IsPresent, $Force.IsPresent)
	Write-LogUtc -Message ('LogPath={0}; BackupPath={1}' -f $script:ResolvedLogPath, $script:ResolvedBackupPath)

	if ($AutoApprove) {
		Write-Warning 'AUTOAPPROVE ENABLED: Confirmation prompts are suppressed, but safety gates remain enforced.'
		Write-LogUtc -Message 'AutoApprove banner displayed.' -Level 'WARN'
	}
	if ($DryRun) {
		Write-Warning 'DRYRUN ENABLED: No changes will be made.'
		Write-LogUtc -Message 'DryRun banner displayed.' -Level 'WARN'
	}
}

function Test-IsAdministrator {
<#
.SYNOPSIS
Checks whether the current PowerShell session is elevated.

.DESCRIPTION
Returns $true when running as Administrator; otherwise $false.

.EXAMPLE
if (-not (Test-IsAdministrator)) { throw 'Admin required.' }
#>
	[CmdletBinding()]
	param()

	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal($identity)
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-OSBuildCompliance {
<#
.SYNOPSIS
Validates the target OS build requirement.

.DESCRIPTION
Confirms Windows 10 build 19045 unless IgnoreOSCheck is specified.

.PARAMETER IgnoreOSCheck
Skips strict validation and returns warning state.

.EXAMPLE
$check = Test-OSBuildCompliance -IgnoreOSCheck:$IgnoreOSCheck
#>
	[CmdletBinding()]
	param(
		[switch]$IgnoreOSCheck
	)

	$result = [pscustomobject]@{
		IsCompliant = $false
		WarningOnly = $false
		Caption     = $null
		Version     = $null
		BuildNumber = $null
		Message     = $null
	}

	$os = Get-CimInstance -ClassName Win32_OperatingSystem
	$result.Caption = $os.Caption
	$result.Version = $os.Version
	$result.BuildNumber = [int]$os.BuildNumber

	if ($result.BuildNumber -eq 19045) {
		$result.IsCompliant = $true
		$result.Message = 'OS build validation passed (19045).'
		return $result
	}

	if ($IgnoreOSCheck) {
		$result.IsCompliant = $true
		$result.WarningOnly = $true
		$result.Message = ('OS build validation bypassed by IgnoreOSCheck. Detected build: {0}' -f $result.BuildNumber)
		return $result
	}

	$result.Message = ('Unsupported OS build. Required: 19045. Detected: {0}' -f $result.BuildNumber)
	return $result
}

function Get-FirmwareTypeLabel {
<#
.SYNOPSIS
Returns firmware type as UEFI or BIOS.

.DESCRIPTION
Maps system firmware type from Win32_ComputerSystem to UEFI/BIOS where possible.

.EXAMPLE
$type = Get-FirmwareTypeLabel
#>
	[CmdletBinding()]
	param()

	$firmware = $null
	try {
		$firmwareReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop
		switch ([int]$firmwareReg.PEFirmwareType) {
			1 { $firmware = 'BIOS' }
			2 { $firmware = 'UEFI' }
			default { $firmware = 'Unknown' }
		}
	}
	catch {
		$firmware = 'Unknown'
	}

	return $firmware
}

function Get-GPUVendorClass {
<#
.SYNOPSIS
Classifies primary GPU vendor.

.DESCRIPTION
Maps video controller adapter compatibility text to NVIDIA, AMD, Intel, or Other.

.EXAMPLE
$gpuVendor = Get-GPUVendorClass
#>
	[CmdletBinding()]
	param()

	$gpu = Get-CimInstance -ClassName Win32_VideoController | Select-Object -First 1
	if ($null -eq $gpu) { return 'Other' }

	$source = ($gpu.AdapterCompatibility + ' ' + $gpu.Name).ToLowerInvariant()

	if ($source -match 'nvidia') { return 'NVIDIA' }
	if ($source -match 'advanced micro devices|amd|radeon') { return 'AMD' }
	if ($source -match 'intel') { return 'Intel' }
	return 'Other'
}

function Get-StorageTypeMap {
<#
.SYNOPSIS
Builds per-volume storage media type map.

.DESCRIPTION
Uses CIM disk and partition relationships to estimate SSD/HDD classification per drive letter.

.EXAMPLE
$map = Get-StorageTypeMap
#>
	[CmdletBinding()]
	param()

	$map = @{}
	$logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
	$drives = Get-CimInstance -ClassName Win32_DiskDrive

	$diskToMedia = @{}
	foreach ($drive in $drives) {
		$media = 'Unknown'
		$modelText = ($drive.Model + ' ' + $drive.MediaType).ToLowerInvariant()
		if ($modelText -match 'ssd|nvme|solid state') {
			$media = 'SSD'
		}
		elseif ($modelText -match 'hdd|hard disk|rotational') {
			$media = 'HDD'
		}
		$diskToMedia[$drive.DeviceID] = $media
	}

	foreach ($ld in $logicalDisks) {
		$driveLetter = $ld.DeviceID
		$mediaType = 'Unknown'

		$partitionRefs = Get-CimAssociatedInstance -InputObject $ld -Association Win32_LogicalDiskToPartition -ErrorAction SilentlyContinue
		foreach ($partition in $partitionRefs) {
			$diskRefs = Get-CimAssociatedInstance -InputObject $partition -Association Win32_DiskDriveToDiskPartition -ErrorAction SilentlyContinue
			foreach ($disk in $diskRefs) {
				if ($diskToMedia.ContainsKey($disk.DeviceID)) {
					$mediaType = $diskToMedia[$disk.DeviceID]
					break
				}
			}
			if ($mediaType -ne 'Unknown') { break }
		}

		if ($mediaType -eq 'Unknown') {
			$mediaType = 'HDD'
		}

		$map[$driveLetter] = $mediaType
	}

	return $map
}

function Get-HardwareProfile {
<#
.SYNOPSIS
Collects hardware profile needed for downstream module decisions.

.DESCRIPTION
Builds a profile containing storage class per volume, RAM, CPU core counts, firmware mode,
free space per volume, and GPU vendor. Uses CIM-based queries for hardware data.

.EXAMPLE
$hardware = Get-HardwareProfile
#>
	[CmdletBinding()]
	param()

	$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
	$processors = Get-CimInstance -ClassName Win32_Processor
	$logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"

	$totalPhysicalCores = 0
	$totalLogicalCores = 0
	foreach ($cpu in $processors) {
		$totalPhysicalCores += [int]$cpu.NumberOfCores
		$totalLogicalCores += [int]$cpu.NumberOfLogicalProcessors
	}

	$freeSpaceMap = @{}
	foreach ($disk in $logicalDisks) {
		$freeGB = [math]::Round(($disk.FreeSpace / 1GB), 2)
		$freeSpaceMap[$disk.DeviceID] = $freeGB
	}

	$profile = [pscustomobject]@{
		StorageType  = Get-StorageTypeMap
		TotalRAMgb   = [math]::Round(($computerSystem.TotalPhysicalMemory / 1GB), 2)
		CPUCores     = [pscustomobject]@{
			Physical = $totalPhysicalCores
			Logical  = $totalLogicalCores
		}
		FirmwareType = Get-FirmwareTypeLabel
		FreeSpaceMap = $freeSpaceMap
		GPUVendor    = Get-GPUVendorClass
	}

	return $profile
}

function Test-SystemDriveFreeSpace {
<#
.SYNOPSIS
Validates minimum free space on system drive.

.DESCRIPTION
Requires at least 2 GB free on system drive or script aborts.

.PARAMETER HardwareProfile
Hardware profile object containing FreeSpaceMap.

.EXAMPLE
Test-SystemDriveFreeSpace -HardwareProfile $HardwareProfile
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile
	)

	$systemDrive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
	if ([string]::IsNullOrWhiteSpace($systemDrive)) {
		throw 'Unable to determine system drive.'
	}

	if (-not $HardwareProfile.FreeSpaceMap.ContainsKey($systemDrive)) {
		throw ("System drive {0} not found in FreeSpaceMap." -f $systemDrive)
	}

	$freeGb = [double]$HardwareProfile.FreeSpaceMap[$systemDrive]
	if ($freeGb -lt 2.0) {
		throw ("System drive free space is below 2 GB. Detected: {0} GB." -f $freeGb)
	}

	Write-LogUtc -Message ("System drive free space check passed: {0}={1} GB" -f $systemDrive, $freeGb)
}

#endregion Core Utilities

#region Module 1

function Invoke-Module1EnvironmentAndHardwareDetection {
<#
.SYNOPSIS
Runs Module 1 environment and hardware detection.

.DESCRIPTION
Validates elevation and OS target requirements, gathers CIM-based hardware profile, and enforces
minimum free space threshold on system drive.

.PARAMETER IgnoreOSCheck
Skips strict build validation and logs warning if set.

.EXAMPLE
$module1 = Invoke-Module1EnvironmentAndHardwareDetection -IgnoreOSCheck:$IgnoreOSCheck
#>
	[CmdletBinding()]
	param(
		[switch]$IgnoreOSCheck
	)

	$result = New-ModuleResult -ModuleName 'Module1-EnvironmentAndHardwareDetection'

	try {
		if (-not (Test-IsAdministrator)) {
			throw 'Administrator privileges are required. Re-run in an elevated PowerShell session.'
		}
		Write-LogUtc -Message 'Elevation check passed.'

		$osCheck = Test-OSBuildCompliance -IgnoreOSCheck:$IgnoreOSCheck
		if (-not $osCheck.IsCompliant) {
			throw $osCheck.Message
		}
		if ($osCheck.WarningOnly) {
			$result.Warnings += $osCheck.Message
			Write-LogUtc -Message $osCheck.Message -Level 'WARN'
		}
		else {
			Write-LogUtc -Message $osCheck.Message
		}

		$hardwareProfile = Get-HardwareProfile
		Test-SystemDriveFreeSpace -HardwareProfile $hardwareProfile

		$result.ChangesApplied += 'Hardware profile collected and validated.'
		$result.ChangesApplied += ('Detected GPUVendor={0}; FirmwareType={1}; RAM={2}GB' -f $hardwareProfile.GPUVendor, $hardwareProfile.FirmwareType, $hardwareProfile.TotalRAMgb)
		$result | Add-Member -MemberType NoteProperty -Name HardwareProfile -Value $hardwareProfile -Force

		Write-LogUtc -Message 'Module 1 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ('Module 1 failed: {0}' -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 1

#region Module 2 Helpers

function Add-DefenderPathExclusion {
<#
.SYNOPSIS
Adds a Windows Defender exclusion path with tracking.

.DESCRIPTION
Adds exclusion entries for paths required by this script and records each successful addition
for guaranteed removal in the final cleanup block.

.PARAMETER Path
Absolute path to exclude.

.EXAMPLE
Add-DefenderPathExclusion -Path $script:ResolvedBackupPath
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	if (-not (Test-Path -Path $Path)) {
		New-Item -Path $Path -ItemType Directory -Force | Out-Null
	}

	if (-not $script:DefenderExclusionsAdded) {
		$script:DefenderExclusionsAdded = @()
	}

	if ($script:DefenderExclusionsAdded -contains $Path) {
		Write-LogUtc -Message ("Defender exclusion already tracked: {0}" -f $Path)
		return
	}

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would add Defender exclusion: {0}" -f $Path) -Level 'WARN'
		return
	}

	if ($PSCmdlet.ShouldProcess($Path, 'Add Windows Defender exclusion path')) {
		Add-MpPreference -ExclusionPath $Path
		$script:DefenderExclusionsAdded += $Path
		Write-LogUtc -Message ("Added Defender exclusion: {0}" -f $Path) -Level 'WARN'
	}
}

function Export-RegistryBackup {
<#
.SYNOPSIS
Exports a registry key to a .reg backup file.

.DESCRIPTION
Uses reg.exe export to save a registry hive/key snapshot for rollback.

.PARAMETER RegistryPath
Registry path in reg.exe syntax.

.PARAMETER DestinationFile
Destination .reg file path.

.EXAMPLE
Export-RegistryBackup -RegistryPath 'HKLM\SOFTWARE\...' -DestinationFile 'C:\Backups\key.reg'
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$RegistryPath,

		[Parameter(Mandatory = $true)]
		[string]$DestinationFile
	)

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would export registry key: {0} -> {1}" -f $RegistryPath, $DestinationFile) -Level 'WARN'
		return $false
	}

	if ($PSCmdlet.ShouldProcess($RegistryPath, 'Export registry key backup')) {
		$null = & reg.exe export $RegistryPath $DestinationFile /y 2>&1
		if ($LASTEXITCODE -ne 0) {
			throw ("Failed to export registry key: {0}" -f $RegistryPath)
		}
		Write-LogUtc -Message ("Exported registry key: {0} -> {1}" -f $RegistryPath, $DestinationFile)
		return $true
	}

	return $false
}

function Export-DataSnapshot {
<#
.SYNOPSIS
Exports snapshot data to JSON and/or CSV.

.DESCRIPTION
Writes snapshot objects for rollback and reporting. Creates JSON and CSV when requested.

.PARAMETER Data
Input object collection.

.PARAMETER BaseFilePath
Base path without extension.

.PARAMETER AsCsv
Also export CSV.

.EXAMPLE
Export-DataSnapshot -Data $services -BaseFilePath 'C:\Backups\Services_20260313T...'
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[object]$Data,

		[Parameter(Mandatory = $true)]
		[string]$BaseFilePath,

		[switch]$AsCsv
	)

	$jsonPath = '{0}.json' -f $BaseFilePath
	$csvPath = '{0}.csv' -f $BaseFilePath

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would export snapshot JSON: {0}" -f $jsonPath) -Level 'WARN'
		if ($AsCsv) {
			Write-LogUtc -Message ("[DryRun] Would export snapshot CSV: {0}" -f $csvPath) -Level 'WARN'
		}
		return [pscustomobject]@{ JsonPath = $jsonPath; CsvPath = ($(if ($AsCsv) { $csvPath } else { $null })) }
	}

	if ($PSCmdlet.ShouldProcess($jsonPath, 'Write JSON snapshot')) {
		$Data | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
		Write-LogUtc -Message ("Snapshot JSON written: {0}" -f $jsonPath)
	}

	if ($AsCsv -and $PSCmdlet.ShouldProcess($csvPath, 'Write CSV snapshot')) {
		$Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
		Write-LogUtc -Message ("Snapshot CSV written: {0}" -f $csvPath)
	}

	return [pscustomobject]@{ JsonPath = $jsonPath; CsvPath = ($(if ($AsCsv) { $csvPath } else { $null })) }
}

function New-BackupManifest {
<#
.SYNOPSIS
Creates an in-memory backup manifest object.

.DESCRIPTION
Initializes manifest metadata and artifact collection. Final persistence is handled by Save-BackupManifest.

.EXAMPLE
$manifest = New-BackupManifest
#>
	[CmdletBinding()]
	param()

	return [pscustomobject]@{
		RunId        = $script:RunId
		CreatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
		Hostname     = $env:COMPUTERNAME
		LogPath      = $script:ResolvedLogPath
		BackupPath   = $script:ResolvedBackupPath
		Artifacts    = @()
	}
}

function Add-BackupManifestArtifact {
<#
.SYNOPSIS
Adds an artifact entry to backup manifest.

.DESCRIPTION
Records backup output metadata including source, destination, timestamp, and existence check.

.PARAMETER Manifest
Manifest object.

.PARAMETER Type
Artifact type label.

.PARAMETER Source
Source identifier.

.PARAMETER Destination
Output path.

.EXAMPLE
$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Registry' -Source 'HKLM\...' -Destination $path
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Manifest,

		[Parameter(Mandatory = $true)]
		[string]$Type,

		[Parameter(Mandatory = $true)]
		[string]$Source,

		[Parameter(Mandatory = $true)]
		[string]$Destination
	)

	$item = [pscustomobject]@{
		Type         = $Type
		Source       = $Source
		Destination  = $Destination
		TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
		Exists       = (Test-Path -Path $Destination)
	}

	$Manifest.Artifacts += $item
	return $Manifest
}

function Save-BackupManifest {
<#
.SYNOPSIS
Persists backup manifest to JSON file.

.DESCRIPTION
Writes manifest to BackupPath with RunId in filename.

.PARAMETER Manifest
Manifest object to write.

.EXAMPLE
$manifestPath = Save-BackupManifest -Manifest $manifest
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Manifest
	)

	$manifestPath = Join-Path -Path $script:ResolvedBackupPath -ChildPath ("BackupManifest_{0}.json" -f $script:RunId)

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would write backup manifest: {0}" -f $manifestPath) -Level 'WARN'
		return $manifestPath
	}

	if ($PSCmdlet.ShouldProcess($manifestPath, 'Write backup manifest')) {
		$Manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding UTF8
		Write-LogUtc -Message ("Backup manifest written: {0}" -f $manifestPath)
	}

	return $manifestPath
}

#endregion Module 2 Helpers

#region Module 2

function Invoke-Module2PrechecksAndBackups {
<#
.SYNOPSIS
Runs Module 2 pre-checks and backup foundation.

.DESCRIPTION
Creates restore point (unless explicitly skipped), adds Defender exclusions for log/backup paths,
exports required registry keys, captures system snapshots, exports drivers, and writes a manifest.

.PARAMETER HardwareProfile
Hardware profile from Module 1.

.PARAMETER SkipRestorePoint
Skips restore point creation when explicitly requested.

.EXAMPLE
$module2 = Invoke-Module2PrechecksAndBackups -HardwareProfile $script:HardwareProfile -SkipRestorePoint:$SkipRestorePoint
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile,

		[switch]$SkipRestorePoint
	)

	$result = New-ModuleResult -ModuleName 'Module2-PrechecksAndBackups'
	$manifest = New-BackupManifest

	try {
		$backupRoot = Join-Path -Path $script:ResolvedBackupPath -ChildPath ("Run_{0}" -f $script:RunId)
		$registryRoot = Join-Path -Path $backupRoot -ChildPath 'Registry'
		$snapshotRoot = Join-Path -Path $backupRoot -ChildPath 'Snapshots'
		$driverExportRoot = Join-Path -Path $backupRoot -ChildPath 'DriversExport'

		foreach ($folder in @($backupRoot, $registryRoot, $snapshotRoot, $driverExportRoot)) {
			if (-not (Test-Path -Path $folder)) {
				if (-not $DryRun) {
					New-Item -Path $folder -ItemType Directory -Force | Out-Null
				}
				Write-LogUtc -Message ($(if ($DryRun) { "[DryRun] Would create folder: $folder" } else { "Created folder: $folder" }))
			}
		}

		if ($SkipRestorePoint) {
			$msg = 'Restore point creation skipped by -SkipRestorePoint.'
			$result.Warnings += $msg
			Write-LogUtc -Message $msg -Level 'WARN'
		}
		elseif ($DryRun) {
			Write-LogUtc -Message '[DryRun] Would create system restore point at script start.' -Level 'WARN'
		}
		else {
			if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Create system restore point')) {
				Checkpoint-Computer -Description ("Optimize-Windows10_{0}" -f $script:RunId) -RestorePointType 'MODIFY_SETTINGS'
				Write-LogUtc -Message 'System restore point created successfully.'
				$result.ChangesApplied += 'System restore point created.'
			}
		}

		Add-DefenderPathExclusion -Path $script:ResolvedLogPath
		Add-DefenderPathExclusion -Path $script:ResolvedBackupPath
		$result.ChangesApplied += 'Defender exclusions evaluated for log and backup paths.'

		$registryTargets = @(
			'HKLM\SYSTEM\CurrentControlSet\Services',
			'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
			'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
		)

		foreach ($target in $registryTargets) {
			$safeName = (($target -replace '[\\/:*?"<>| ]', '_').Trim('_'))
			$destination = Join-Path -Path $registryRoot -ChildPath ("{0}_{1}.reg" -f $safeName, $script:RunId)
			$exported = Export-RegistryBackup -RegistryPath $target -DestinationFile $destination
			if ($exported -or $DryRun) {
				$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Registry' -Source $target -Destination $destination
				$result.ChangesApplied += ("Registry backup prepared: {0}" -f $target)
			}
		}

		$apps = @()
		try { $apps += Get-Package -ErrorAction Stop | Select-Object Name, Version, ProviderName, Source } catch { Write-LogUtc -Message ("Get-Package failed: {0}" -f $_.Exception.Message) -Level 'WARN'; $result.Warnings += 'Get-Package snapshot incomplete.' }
		try { $apps += Get-AppxPackage -ErrorAction Stop | Select-Object Name, Version, Publisher, InstallLocation } catch { Write-LogUtc -Message ("Get-AppxPackage failed: {0}" -f $_.Exception.Message) -Level 'WARN'; $result.Warnings += 'Get-AppxPackage snapshot incomplete.' }

		$appsExport = Export-DataSnapshot -Data $apps -BaseFilePath (Join-Path -Path $snapshotRoot -ChildPath ("InstalledApps_{0}" -f $script:RunId)) -AsCsv
		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Installed applications' -Destination $appsExport.JsonPath
		if ($appsExport.CsvPath) { $manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Installed applications CSV' -Destination $appsExport.CsvPath }

		$tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
		$tasksExport = Export-DataSnapshot -Data $tasks -BaseFilePath (Join-Path -Path $snapshotRoot -ChildPath ("ScheduledTasks_{0}" -f $script:RunId)) -AsCsv
		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Scheduled tasks' -Destination $tasksExport.JsonPath
		if ($tasksExport.CsvPath) { $manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Scheduled tasks CSV' -Destination $tasksExport.CsvPath }

		$services = Get-Service | Select-Object Name, DisplayName, Status, StartType
		$servicesExport = Export-DataSnapshot -Data $services -BaseFilePath (Join-Path -Path $snapshotRoot -ChildPath ("Services_{0}" -f $script:RunId)) -AsCsv
		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Services' -Destination $servicesExport.JsonPath
		if ($servicesExport.CsvPath) { $manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Services CSV' -Destination $servicesExport.CsvPath }

		$startup = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User
		$startupExport = Export-DataSnapshot -Data $startup -BaseFilePath (Join-Path -Path $snapshotRoot -ChildPath ("StartupCommands_{0}" -f $script:RunId)) -AsCsv
		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Startup commands' -Destination $startupExport.JsonPath
		if ($startupExport.CsvPath) { $manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'Startup commands CSV' -Destination $startupExport.CsvPath }

		$driversEnumPath = Join-Path -Path $snapshotRoot -ChildPath ("PnPUtil_EnumDrivers_{0}.txt" -f $script:RunId)
		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would snapshot drivers enumeration to: {0}" -f $driversEnumPath) -Level 'WARN'
		}
		else {
			if ($PSCmdlet.ShouldProcess($driversEnumPath, 'Capture pnputil /enum-drivers snapshot')) {
				$driverEnumOutput = & pnputil.exe /enum-drivers 2>&1
				$driverEnumOutput | Set-Content -Path $driversEnumPath -Encoding UTF8
				Write-LogUtc -Message ("Driver snapshot captured: {0}" -f $driversEnumPath)
			}
		}
		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'pnputil /enum-drivers' -Destination $driversEnumPath

		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would export third-party drivers to: {0}" -f $driverExportRoot) -Level 'WARN'
		}
		else {
			if ($PSCmdlet.ShouldProcess($driverExportRoot, 'Export third-party drivers')) {
				$driverExportOutput = & pnputil.exe /export-driver * $driverExportRoot 2>&1
				Write-LogUtc -Message ("Third-party driver export completed: {0}" -f $driverExportRoot)
				$driverExportLogPath = Join-Path -Path $snapshotRoot -ChildPath ("PnPUtil_ExportDrivers_{0}.txt" -f $script:RunId)
				$driverExportOutput | Set-Content -Path $driverExportLogPath -Encoding UTF8
				$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Snapshot' -Source 'pnputil /export-driver output' -Destination $driverExportLogPath
			}
		}

		$manifest = Add-BackupManifestArtifact -Manifest $manifest -Type 'Backup' -Source 'Third-party drivers export root' -Destination $driverExportRoot
		$manifestPath = Save-BackupManifest -Manifest $manifest
		$result.ChangesApplied += 'Backup manifest recorded.'
		$result | Add-Member -MemberType NoteProperty -Name BackupManifestPath -Value $manifestPath -Force
		$result | Add-Member -MemberType NoteProperty -Name BackupRootPath -Value $backupRoot -Force

		Write-LogUtc -Message 'Module 2 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 2 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 2

#region Module 3 Helpers

function Request-ExplicitRuntimeConfirmation {
<#
.SYNOPSIS
Prompts for explicit runtime confirmation that cannot be auto-skipped.

.DESCRIPTION
Requires operator to type YES for high-sensitivity operations. This confirmation is not bypassed
by AutoApprove to satisfy mandatory safety policy.

.PARAMETER PromptMessage
Message shown to operator.

.EXAMPLE
$ok = Request-ExplicitRuntimeConfirmation -PromptMessage 'Proceed with action?'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$PromptMessage
	)

	$response = Read-Host ("{0} Type YES to continue" -f $PromptMessage)
	return ($response -ceq 'YES')
}

function Get-PermanentExclusionPatterns {
<#
.SYNOPSIS
Returns permanent exclusion path patterns.

.DESCRIPTION
These patterns represent paths/data that must never be modified by cleanup routines.

.EXAMPLE
$patterns = Get-PermanentExclusionPatterns
#>
	[CmdletBinding()]
	param()

	return @(
		'C:\Users\*\AppData\Roaming\Microsoft\Credentials*',
		'C:\Users\*\AppData\Local\Microsoft\Credentials*',
		'C:\Users\*\AppData\Local\Microsoft\Vault*',
		'C:\Users\*\AppData\Roaming\Microsoft\Protect*',
		'C:\Users\*\AppData\Local\Google\Chrome\User Data*',
		'C:\Users\*\AppData\Local\Microsoft\Edge\User Data*',
		'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles*',
		'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc*',
		'C:\ProgramData\Microsoft\Search\Data*'
	)
}

function Test-IsPathPermanentlyExcluded {
<#
.SYNOPSIS
Determines whether path matches permanent exclusion rules.

.DESCRIPTION
Returns $true if the path falls under non-negotiable exclusion patterns.

.PARAMETER Path
Path to evaluate.

.EXAMPLE
if (Test-IsPathPermanentlyExcluded -Path $target) { ... }
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	$full = [System.IO.Path]::GetFullPath($Path)
	foreach ($pattern in (Get-PermanentExclusionPatterns)) {
		if ($full -like $pattern) {
			return $true
		}
	}
	return $false
}

function Backup-TargetPath {
<#
.SYNOPSIS
Creates backup copy before destructive action.

.DESCRIPTION
Copies target content to backup staging area and returns backup location.
No deletion should proceed if backup fails unless explicit Force exception path is documented.

.PARAMETER TargetPath
Path to back up.

.PARAMETER BackupRoot
Root backup folder.

.PARAMETER Label
Label used in backup folder naming.

.EXAMPLE
$backup = Backup-TargetPath -TargetPath $Path -BackupRoot $script:BackupRootPath -Label 'WindowsTemp'
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$TargetPath,

		[Parameter(Mandatory = $true)]
		[string]$BackupRoot,

		[Parameter(Mandatory = $true)]
		[string]$Label
	)

	if (-not (Test-Path -Path $TargetPath)) {
		Write-LogUtc -Message ("Backup skipped (path missing): {0}" -f $TargetPath)
		return $null
	}

	$safeLabel = ($Label -replace '[^A-Za-z0-9_\-]', '_')
	$dest = Join-Path -Path $BackupRoot -ChildPath ("PreDelete_{0}_{1}" -f $safeLabel, (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would back up target path: {0} -> {1}" -f $TargetPath, $dest) -Level 'WARN'
		return $dest
	}

	if ($PSCmdlet.ShouldProcess($TargetPath, ("Backup path to {0}" -f $dest))) {
		New-Item -Path $dest -ItemType Directory -Force | Out-Null
		Copy-Item -Path $TargetPath -Destination $dest -Recurse -Force -ErrorAction Stop
		Write-LogUtc -Message ("Backup created: {0} -> {1}" -f $TargetPath, $dest)
	}

	return $dest
}

function Clear-DirectoryFilesSafe {
<#
.SYNOPSIS
Clears directory contents with exclusion and lock handling.

.DESCRIPTION
Backs up target first, then removes items while skipping locked files and logging each skip.

.PARAMETER TargetPath
Directory whose contents should be cleared.

.PARAMETER BackupRoot
Backup root path.

.PARAMETER Label
Operation label for backup naming.

.PARAMETER RequireExplicitConfirmation
When set, requires explicit runtime YES confirmation.

.EXAMPLE
Clear-DirectoryFilesSafe -TargetPath 'C:\Windows\Temp' -BackupRoot $script:BackupRootPath -Label 'WindowsTemp'
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$TargetPath,

		[Parameter(Mandatory = $true)]
		[string]$BackupRoot,

		[Parameter(Mandatory = $true)]
		[string]$Label,

		[switch]$RequireExplicitConfirmation
	)

	if (-not (Test-Path -Path $TargetPath -PathType Container)) {
		Write-LogUtc -Message ("Cleanup skipped (directory missing): {0}" -f $TargetPath)
		return [pscustomobject]@{ Removed = 0; Skipped = 0; BackupPath = $null; Confirmed = $true }
	}

	if (Test-IsPathPermanentlyExcluded -Path $TargetPath) {
		Write-LogUtc -Message ("Cleanup blocked by permanent exclusion: {0}" -f $TargetPath) -Level 'WARN'
		return [pscustomobject]@{ Removed = 0; Skipped = 0; BackupPath = $null; Confirmed = $false }
	}

	if ($RequireExplicitConfirmation) {
		$confirmed = Request-ExplicitRuntimeConfirmation -PromptMessage ("Sensitive path cleanup requested: {0}." -f $TargetPath)
		if (-not $confirmed) {
			Write-LogUtc -Message ("Operator declined explicit cleanup confirmation for: {0}" -f $TargetPath) -Level 'WARN'
			return [pscustomobject]@{ Removed = 0; Skipped = 0; BackupPath = $null; Confirmed = $false }
		}
	}

	$backupPath = Backup-TargetPath -TargetPath $TargetPath -BackupRoot $BackupRoot -Label $Label
	if (-not $backupPath -and -not $DryRun) {
		throw ("Backup requirement failed for destructive action: {0}" -f $TargetPath)
	}

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would clear directory contents: {0}" -f $TargetPath) -Level 'WARN'
		return [pscustomobject]@{ Removed = 0; Skipped = 0; BackupPath = $backupPath; Confirmed = $true }
	}

	$removed = 0
	$skipped = 0
	$items = Get-ChildItem -Path $TargetPath -Force -ErrorAction SilentlyContinue
	foreach ($item in $items) {
		try {
			if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove item')) {
				Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
				$removed++
			}
		}
		catch {
			$skipped++
			Write-LogUtc -Message ("Skipped locked/protected item: {0}; Reason: {1}" -f $item.FullName, $_.Exception.Message) -Level 'WARN'
		}
	}

	Write-LogUtc -Message ("Cleanup summary for {0}: Removed={1}; Skipped={2}" -f $TargetPath, $removed, $skipped)
	return [pscustomobject]@{ Removed = $removed; Skipped = $skipped; BackupPath = $backupPath; Confirmed = $true }
}

function Invoke-SoftwareDistributionCleanup {
<#
.SYNOPSIS
Safely clears SoftwareDistribution\Download with backup and free-space guard.

.DESCRIPTION
Computes backup feasibility, enforces >80% free-space guard, requires Force for no-backup proceed path,
stops/starts wuauserv, and logs all outcomes.

.PARAMETER BackupRoot
Backup root path for pre-delete copy.

.EXAMPLE
Invoke-SoftwareDistributionCleanup -BackupRoot $script:BackupRootPath
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$BackupRoot
	)

	$target = 'C:\Windows\SoftwareDistribution\Download'
	if (-not (Test-Path -Path $target)) {
		Write-LogUtc -Message 'SoftwareDistribution\Download not found; skipping.'
		return [pscustomobject]@{ Cleared = $false; BackupPath = $null; UsedForceNoBackup = $false }
	}

	$systemDrive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
	$driveInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive)
	$freeBytes = [double]$driveInfo.FreeSpace

	$folderBytes = (Get-ChildItem -Path $target -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	if (-not $folderBytes) { $folderBytes = 0.0 }

	$requiresForceNoBackup = $false
	if ($freeBytes -gt 0 -and (($folderBytes / $freeBytes) -gt 0.8)) {
		$requiresForceNoBackup = $true
	}

	$backupPath = $null
	$usedForceNoBackup = $false

	if ($requiresForceNoBackup) {
		Write-LogUtc -Message 'SoftwareDistribution backup exceeds 80% free-space threshold.' -Level 'WARN'
		if (-not $Force) {
			Write-LogUtc -Message 'Skipping SoftwareDistribution cleanup because Force was not specified for no-backup path.' -Level 'WARN'
			return [pscustomobject]@{ Cleared = $false; BackupPath = $null; UsedForceNoBackup = $false }
		}

		$usedForceNoBackup = $true
		Write-LogUtc -Message 'Proceeding with SoftwareDistribution cleanup without backup due to Force override.' -Level 'WARN'
	}
	else {
		$backupPath = Backup-TargetPath -TargetPath $target -BackupRoot $BackupRoot -Label 'SoftwareDistributionDownload'
		if (-not $backupPath -and -not $DryRun) {
			throw 'SoftwareDistribution cleanup blocked because backup was not created.'
		}
	}

	if ($DryRun) {
		Write-LogUtc -Message '[DryRun] Would stop wuauserv, clear SoftwareDistribution\Download, and restart wuauserv.' -Level 'WARN'
		return [pscustomobject]@{ Cleared = $false; BackupPath = $backupPath; UsedForceNoBackup = $usedForceNoBackup }
	}

	$serviceStopped = $false
	try {
		if ($PSCmdlet.ShouldProcess('wuauserv', 'Stop Windows Update service')) {
			Stop-Service -Name wuauserv -Force -ErrorAction Stop
			$serviceStopped = $true
			Write-LogUtc -Message 'Stopped service: wuauserv'
		}

		$items = Get-ChildItem -Path $target -Force -ErrorAction SilentlyContinue
		foreach ($item in $items) {
			try {
				if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove SoftwareDistribution item')) {
					Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
				}
			}
			catch {
				Write-LogUtc -Message ("SoftwareDistribution item skip: {0}; Reason: {1}" -f $item.FullName, $_.Exception.Message) -Level 'WARN'
			}
		}

		Write-LogUtc -Message 'Cleared SoftwareDistribution\Download contents.'
		return [pscustomobject]@{ Cleared = $true; BackupPath = $backupPath; UsedForceNoBackup = $usedForceNoBackup }
	}
	finally {
		if ($serviceStopped) {
			try {
				Start-Service -Name wuauserv -ErrorAction Stop
				Write-LogUtc -Message 'Restarted service: wuauserv'
			}
			catch {
				Write-LogUtc -Message ("Failed to restart wuauserv: {0}" -f $_.Exception.Message) -Level 'ERROR'
			}
		}
	}
}

function Invoke-StorageOptimization {
<#
.SYNOPSIS
Runs ReTrim/Defrag based on storage type and free-space thresholds.

.DESCRIPTION
Uses hardware profile storage map to apply ReTrim on SSD and Defrag on HDD only when
free space is at least 15% for that volume.

.PARAMETER HardwareProfile
Hardware profile object from Module 1.

.EXAMPLE
Invoke-StorageOptimization -HardwareProfile $script:HardwareProfile
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile
	)

	$results = @()
	$logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"

	foreach ($disk in $logicalDisks) {
		$letter = $disk.DeviceID
		$freePercent = if ($disk.Size -gt 0) { [math]::Round((($disk.FreeSpace / $disk.Size) * 100), 2) } else { 0 }
		$kind = 'HDD'
		if ($HardwareProfile.StorageType.ContainsKey($letter)) {
			$kind = [string]$HardwareProfile.StorageType[$letter]
		}

		if ($kind -eq 'SSD') {
			if ($DryRun) {
				Write-LogUtc -Message ("[DryRun] Would run ReTrim on {0}" -f $letter) -Level 'WARN'
			}
			else {
				if ($PSCmdlet.ShouldProcess($letter, 'Optimize-Volume -ReTrim')) {
					Optimize-Volume -DriveLetter $letter.TrimEnd(':') -ReTrim -Verbose:$false
					Write-LogUtc -Message ("ReTrim completed for SSD volume: {0}" -f $letter)
				}
			}
			$results += ("{0}:ReTrim" -f $letter)
		}
		else {
			if ($freePercent -lt 15) {
				Write-LogUtc -Message ("Skipped defrag for {0}: free space {1}% < 15% threshold." -f $letter, $freePercent) -Level 'WARN'
				$results += ("{0}:DefragSkippedLowFreeSpace" -f $letter)
				continue
			}

			if ($DryRun) {
				Write-LogUtc -Message ("[DryRun] Would run Defrag on {0}" -f $letter) -Level 'WARN'
			}
			else {
				if ($PSCmdlet.ShouldProcess($letter, 'Optimize-Volume -Defrag')) {
					Optimize-Volume -DriveLetter $letter.TrimEnd(':') -Defrag -Verbose:$false
					Write-LogUtc -Message ("Defrag completed for HDD volume: {0}" -f $letter)
				}
			}
			$results += ("{0}:Defrag" -f $letter)
		}
	}

	return $results
}

#endregion Module 3 Helpers

#region Module 3

function Invoke-Module3SafeCleanup {
<#
.SYNOPSIS
Runs Module 3 safe cleanup routines.

.DESCRIPTION
Performs guarded cleanup tasks with permanent exclusions, backup-before-delete policy,
forced confirmation requirements for sensitive paths, storage optimization decisions,
and comprehensive logging.

.PARAMETER HardwareProfile
Hardware profile object from Module 1.

.PARAMETER BackupRootPath
Root backup path created in Module 2.

.PARAMETER CleanupAgeDays
Minimum age in days for orphaned temp file removal.

.EXAMPLE
$module3 = Invoke-Module3SafeCleanup -HardwareProfile $script:HardwareProfile -BackupRootPath $script:BackupRootPath -CleanupAgeDays $CleanupAgeDays
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile,

		[Parameter(Mandatory = $true)]
		[string]$BackupRootPath,

		[Parameter(Mandatory = $true)]
		[int]$CleanupAgeDays
	)

	$result = New-ModuleResult -ModuleName 'Module3-SafeCleanup'

	try {
		$cleanupChanges = @()

		$profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {
			$_.LocalPath -like 'C:\Users\*' -and -not $_.Special
		}

		foreach ($profile in $profiles) {
			$userTemp = Join-Path -Path $profile.LocalPath -ChildPath 'AppData\Local\Temp'
			if (-not (Test-Path -Path $userTemp)) { continue }

			$confirmed = Request-ExplicitRuntimeConfirmation -PromptMessage ("Clear per-user Temp for [{0}] at [{1}]?" -f $profile.LocalPath, $userTemp)
			if (-not $confirmed) {
				$result.Warnings += ("Skipped per-user temp cleanup by operator decision: {0}" -f $userTemp)
				Write-LogUtc -Message ("Skipped per-user temp cleanup by operator decision: {0}" -f $userTemp) -Level 'WARN'
				continue
			}

			$userTempResult = Clear-DirectoryFilesSafe -TargetPath $userTemp -BackupRoot $BackupRootPath -Label ("UserTemp_{0}" -f (($profile.LocalPath -replace '[^A-Za-z0-9]', '_'))) -RequireExplicitConfirmation:$false
			$cleanupChanges += ("UserTemp={0};Removed={1};Skipped={2}" -f $userTemp, $userTempResult.Removed, $userTempResult.Skipped)
		}

		$winTempResult = Clear-DirectoryFilesSafe -TargetPath 'C:\Windows\Temp' -BackupRoot $BackupRootPath -Label 'WindowsTemp'
		$cleanupChanges += ("WindowsTemp Removed={0};Skipped={1}" -f $winTempResult.Removed, $winTempResult.Skipped)

		if ($DryRun) {
			Write-LogUtc -Message '[DryRun] Would invoke cleanmgr /sagerun:1' -Level 'WARN'
		}
		else {
			if ($PSCmdlet.ShouldProcess('cleanmgr.exe', 'Run Disk Cleanup (sagerun:1)')) {
				$cleanMgrOutput = & cleanmgr.exe /sagerun:1 2>&1
				$cleanMgrLog = Join-Path -Path $script:ResolvedLogPath -ChildPath ("cleanmgr_{0}.log" -f $script:RunId)
				$cleanMgrOutput | Set-Content -Path $cleanMgrLog -Encoding UTF8
				Write-LogUtc -Message ("Disk Cleanup completed. Output log: {0}" -f $cleanMgrLog)
				$cleanupChanges += 'DiskCleanupExecuted'
			}
		}

		$sdResult = Invoke-SoftwareDistributionCleanup -BackupRoot $BackupRootPath
		$cleanupChanges += ("SoftwareDistribution Cleared={0};ForceNoBackup={1}" -f $sdResult.Cleared, $sdResult.UsedForceNoBackup)
		if ($sdResult.UsedForceNoBackup) {
			$result.Warnings += 'SoftwareDistribution was cleared without backup due to >80% free-space guard and Force override.'
		}

		if ($DryRun) {
			Write-LogUtc -Message '[DryRun] Would clear Delivery Optimization cache.' -Level 'WARN'
		}
		else {
			if ($PSCmdlet.ShouldProcess('DeliveryOptimization', 'Clear Delivery Optimization cache')) {
				try {
					Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
					Write-LogUtc -Message 'Delivery Optimization cache cleared.'
					$cleanupChanges += 'DeliveryOptimizationCacheCleared'
				}
				catch {
					Write-LogUtc -Message ("Delivery Optimization cache clear failed: {0}" -f $_.Exception.Message) -Level 'WARN'
					$result.Warnings += 'Delivery Optimization cache cleanup failed or not available.'
				}
			}
		}

		$orphanRoots = @(
			'C:\Windows\Temp',
			'C:\ProgramData\Temp',
			'C:\Temp'
		)
		$cutoff = (Get-Date).AddDays(-1 * $CleanupAgeDays)
		foreach ($root in $orphanRoots) {
			if (-not (Test-Path -Path $root)) { continue }
			if (Test-IsPathPermanentlyExcluded -Path $root) { continue }

			if ($DryRun) {
				Write-LogUtc -Message ("[DryRun] Would remove orphaned temp files older than {0} days in {1}" -f $CleanupAgeDays, $root) -Level 'WARN'
				continue
			}

			$oldFiles = Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff }
			foreach ($f in $oldFiles) {
				try {
					if ($PSCmdlet.ShouldProcess($f.FullName, 'Remove orphaned temp file')) {
						Remove-Item -Path $f.FullName -Force -ErrorAction Stop
					}
				}
				catch {
					Write-LogUtc -Message ("Skipped orphaned file: {0}; Reason: {1}" -f $f.FullName, $_.Exception.Message) -Level 'WARN'
				}
			}
			$cleanupChanges += ("OrphanedTempProcessed={0}" -f $root)
		}

		$storageOps = Invoke-StorageOptimization -HardwareProfile $HardwareProfile
		$cleanupChanges += $storageOps

		if ($AutoApprove -and -not $Force) {
			Write-LogUtc -Message 'Prefetch cleanup skipped: AutoApprove present without Force.' -Level 'WARN'
			$result.Warnings += 'Prefetch cleanup skipped because AutoApprove requires Force for this action.'
		}
		else {
			$prefetchPath = 'C:\Windows\Prefetch'
			if (Test-Path -Path $prefetchPath) {
				$prefetchConfirm = Request-ExplicitRuntimeConfirmation -PromptMessage 'Clear Prefetch files for this run?'
				if ($prefetchConfirm) {
					$prefetchResult = Clear-DirectoryFilesSafe -TargetPath $prefetchPath -BackupRoot $BackupRootPath -Label 'Prefetch'
					$cleanupChanges += ("Prefetch Removed={0};Skipped={1}" -f $prefetchResult.Removed, $prefetchResult.Skipped)
				}
				else {
					Write-LogUtc -Message 'Prefetch cleanup declined by operator.'
					$result.Warnings += 'Prefetch cleanup declined by operator.'
				}
			}
		}

		$result.ChangesApplied += $cleanupChanges
		Write-LogUtc -Message 'Module 3 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 3 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 3

#region Module 4 Helpers

function Get-PnPUtilDriverRecords {
<#
.SYNOPSIS
Parses pnputil driver enumeration into structured records.

.DESCRIPTION
Runs pnputil /enum-drivers and transforms key fields into objects for deduplication planning.

.EXAMPLE
$records = Get-PnPUtilDriverRecords
#>
	[CmdletBinding()]
	param()

	$output = & pnputil.exe /enum-drivers 2>&1
	$records = @()
	$current = @{}

	foreach ($line in $output) {
		if ($line -match '^\s*$') {
			if ($current.ContainsKey('PublishedName')) {
				$records += [pscustomobject]@{
					INFName         = $current.PublishedName
					ProviderName    = $current.ProviderName
					DriverClass     = $current.ClassName
					DriverVersion   = $current.DriverVersion
					Signer          = $current.SignerName
					PublishedDate   = $current.DriverDate
					HardwareId      = $null
					DeviceInstanceId = $null
					PackageName     = $current.OriginalName
					DriverStorePath = $null
				}
			}
			$current = @{}
			continue
		}

		if ($line -match '^\s*Published Name\s*:\s*(.+)$') { $current.PublishedName = $matches[1].Trim(); continue }
		if ($line -match '^\s*Original Name\s*:\s*(.+)$') { $current.OriginalName = $matches[1].Trim(); continue }
		if ($line -match '^\s*Provider Name\s*:\s*(.+)$') { $current.ProviderName = $matches[1].Trim(); continue }
		if ($line -match '^\s*Class Name\s*:\s*(.+)$') { $current.ClassName = $matches[1].Trim(); continue }
		if ($line -match '^\s*Signer Name\s*:\s*(.+)$') { $current.SignerName = $matches[1].Trim(); continue }
		if ($line -match '^\s*Driver Date and Version\s*:\s*(.+)$') {
			$dv = $matches[1].Trim()
			$current.DriverDate = $dv
			$current.DriverVersion = ($dv -split '\s+')[ -1 ]
			continue
		}
	}

	if ($current.ContainsKey('PublishedName')) {
		$records += [pscustomobject]@{
			INFName         = $current.PublishedName
			ProviderName    = $current.ProviderName
			DriverClass     = $current.ClassName
			DriverVersion   = $current.DriverVersion
			Signer          = $current.SignerName
			PublishedDate   = $current.DriverDate
			HardwareId      = $null
			DeviceInstanceId = $null
			PackageName     = $current.OriginalName
			DriverStorePath = $null
		}
	}

	# Enrich with Win32_PnPSignedDriver hardware and device mapping.
	$signed = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
		Select-Object DeviceID, InfName, DriverVersion, DriverProviderName, IsSigned, DriverDate

	foreach ($rec in $records) {
		$match = $signed | Where-Object { $_.InfName -eq $rec.INFName } | Select-Object -First 1
		if ($match) {
			$rec.HardwareId = $match.DeviceID
			$rec.DeviceInstanceId = $match.DeviceID
			if ($match.DriverVersion) { $rec.DriverVersion = [string]$match.DriverVersion }
			if ($match.DriverProviderName) { $rec.ProviderName = [string]$match.DriverProviderName }
		}
	}

	return $records
}

function Get-LoadedDriverBinarySet {
<#
.SYNOPSIS
Gets loaded driver binary names from driverquery.

.DESCRIPTION
Collects loaded kernel driver module names as a supplemental in-use signal.

.EXAMPLE
$loaded = Get-LoadedDriverBinarySet
#>
	[CmdletBinding()]
	param()

	$csv = & driverquery.exe /FO CSV /V 2>$null | ConvertFrom-Csv
	$set = New-Object System.Collections.Generic.HashSet[string]
	foreach ($row in $csv) {
		if ($row.'Path Name') {
			$fileName = [System.IO.Path]::GetFileName($row.'Path Name')
			if ($fileName) {
				[void]$set.Add($fileName.ToLowerInvariant())
			}
		}
	}
	return $set
}

function Get-ProtectedDriverInfSet {
<#
.SYNOPSIS
Determines INFs considered in-use/protected.

.DESCRIPTION
Marks drivers as protected when bound to PnP devices in OK/Unknown state. Also logs loaded-driver
evidence from driverquery for additional context.

.EXAMPLE
$protected = Get-ProtectedDriverInfSet
#>
	[CmdletBinding()]
	param()

	$protected = New-Object System.Collections.Generic.HashSet[string]

	$pnp = Get-PnpDevice -ErrorAction SilentlyContinue | Select-Object InstanceId, Status
	$signed = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
		Select-Object DeviceID, InfName, DriverName

	foreach ($drv in $signed) {
		if (-not $drv.InfName) { continue }
		$device = $pnp | Where-Object { $_.InstanceId -eq $drv.DeviceID } | Select-Object -First 1
		if ($device -and ($device.Status -eq 'OK' -or $device.Status -eq 'Unknown')) {
			[void]$protected.Add($drv.InfName)
		}
	}

	$loaded = Get-LoadedDriverBinarySet
	Write-LogUtc -Message ("Loaded driver binary sample count from driverquery: {0}" -f $loaded.Count)
	return $protected
}

function Test-IsTrustedSigner {
<#
.SYNOPSIS
Evaluates signer trust class.

.DESCRIPTION
Returns trust rank for selection algorithm.

.PARAMETER Signer
Signer text from pnputil record.

.EXAMPLE
$rank = Test-IsTrustedSigner -Signer $record.Signer
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false)]
		[string]$Signer
	)

	if (-not $Signer) { return 0 }
	$s = $Signer.ToLowerInvariant()
	if ($s -match 'microsoft') { return 3 }
	if ($s -match 'windows hardware compatibility publisher|publisher|corporation|inc\.|llc') { return 2 }
	if ($s -match 'unsigned|not signed|unknown') { return 0 }
	return 1
}

function Get-VersionObjectSafe {
<#
.SYNOPSIS
Converts version text to System.Version safely.

.DESCRIPTION
Fallbacks to 0.0.0.0 when version parsing fails.

.PARAMETER VersionText
Version string.

.EXAMPLE
$v = Get-VersionObjectSafe -VersionText $record.DriverVersion
#>
	[CmdletBinding()]
	param(
		[string]$VersionText
	)

	try {
		return [version]$VersionText
	}
	catch {
		return [version]'0.0.0.0'
	}
}

function Get-DriverDeduplicationPlan {
<#
.SYNOPSIS
Builds duplicate-driver keep/remove plan.

.DESCRIPTION
Groups drivers by hardware identity and applies selection logic:
highest version, signer preference, trusted fallback, protected override.

.PARAMETER DriverRecords
Parsed driver records.

.PARAMETER ProtectedInfSet
Set of INF names considered protected.

.EXAMPLE
$plan = Get-DriverDeduplicationPlan -DriverRecords $records -ProtectedInfSet $protected
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[array]$DriverRecords,

		[Parameter(Mandatory = $true)]
		[object]$ProtectedInfSet
	)

	$groups = $DriverRecords | Group-Object {
		if ($_.HardwareId) {
			$_.HardwareId
		}
		elseif ($_.DeviceInstanceId) {
			$_.DeviceInstanceId
		}
		else {
			"INFONLY::{0}" -f $_.INFName
		}
	}

	$plan = @()

	foreach ($g in $groups) {
		if ($g.Count -le 1) { continue }

		$items = $g.Group
		$protectedItems = $items | Where-Object { $ProtectedInfSet.Contains($_.INFName) }

		$keep = $null
		$reason = $null

		if ($protectedItems.Count -gt 0) {
			$keep = $protectedItems | Sort-Object { Get-VersionObjectSafe -VersionText $_.DriverVersion } -Descending | Select-Object -First 1
			$reason = 'Protected in-use driver retained.'
		}
		else {
			$sorted = $items | Sort-Object `
				@{ Expression = { Get-VersionObjectSafe -VersionText $_.DriverVersion }; Descending = $true }, `
				@{ Expression = { Test-IsTrustedSigner -Signer $_.Signer }; Descending = $true }

			$top = $sorted | Select-Object -First 1
			$topTrust = Test-IsTrustedSigner -Signer $top.Signer

			if ($topTrust -eq 0) {
				$trusted = $sorted | Where-Object { (Test-IsTrustedSigner -Signer $_.Signer) -ge 2 } | Select-Object -First 1
				if ($trusted) {
					$keep = $trusted
					$reason = 'Newest was untrusted/unsigned; retained latest trusted driver.'
				}
				else {
					$keep = $top
					$reason = 'No trusted alternative available; retained highest version.'
				}
			}
			else {
				$keep = $top
				$reason = 'Retained highest version with signer preference.'
			}
		}

		$remove = $items | Where-Object { $_.INFName -ne $keep.INFName }

		$plan += [pscustomobject]@{
			GroupKey           = $g.Name
			HardwareId         = $keep.HardwareId
			DeviceInstanceId   = $keep.DeviceInstanceId
			DriverToKeep       = $keep
			DriversToRemove    = @($remove)
			Reason             = $reason
			InUseProtected     = ($protectedItems.Count -gt 0)
		}
	}

	return $plan
}

function Request-StandardConfirmation {
<#
.SYNOPSIS
Requests standard yes/no confirmation.

.DESCRIPTION
Uses AutoApprove to skip interaction unless explicit user response is required.

.PARAMETER Message
Prompt message.

.EXAMPLE
$ok = Request-StandardConfirmation -Message 'Remove driver oem12.inf?'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message
	)

	if ($AutoApprove) {
		Write-LogUtc -Message ("AutoApprove accepted confirmation prompt: {0}" -f $Message) -Level 'WARN'
		return $true
	}

	$inputValue = Read-Host ("{0} Type Y to continue" -f $Message)
	return ($inputValue -match '^(Y|y)$')
}

function Get-DriverRemovalManifestPath {
	[CmdletBinding()]
	param()

	return (Join-Path -Path $script:ResolvedBackupPath -ChildPath ("DriverRemovalManifest_{0}.json" -f $script:RunId))
}

function Add-DriverRemovalManifestEntry {
<#
.SYNOPSIS
Appends entry to driver removal manifest.

.DESCRIPTION
Maintains a JSON array manifest for each driver removal backup and action.

.PARAMETER Entry
Entry object.

.EXAMPLE
Add-DriverRemovalManifestEntry -Entry $entry
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Entry
	)

	$path = Get-DriverRemovalManifestPath
	$list = @()
	if (Test-Path -Path $path) {
		$existing = Get-Content -Path $path -Raw | ConvertFrom-Json
		if ($existing -is [System.Array]) { $list = @($existing) } else { $list = @($existing) }
	}

	$list += $Entry
	$list | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
	Write-LogUtc -Message ("Driver removal manifest appended: {0}" -f $path)
}

#endregion Module 4 Helpers

#region Module 4

function Invoke-Module4DriverManagement {
<#
.SYNOPSIS
Runs Module 4 duplicate driver preview/removal workflow.

.DESCRIPTION
Enumerates drivers, builds deduplication plan, supports preview-only mode, and executes
backup -> manifest -> confirmation -> delete -> verify -> rollback chain for removals.

.PARAMETER HardwareProfile
Hardware profile from Module 1.

.PARAMETER BackupRootPath
Backup root from Module 2.

.PARAMETER PreviewDriversToRemove
Preview-only mode.

.PARAMETER RemoveDuplicateDrivers
Enable removal mode.

.EXAMPLE
$module4 = Invoke-Module4DriverManagement -HardwareProfile $script:HardwareProfile -BackupRootPath $script:BackupRootPath -PreviewDriversToRemove:$PreviewDriversToRemove -RemoveDuplicateDrivers:$RemoveDuplicateDrivers
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile,

		[Parameter(Mandatory = $true)]
		[string]$BackupRootPath,

		[switch]$PreviewDriversToRemove,
		[switch]$RemoveDuplicateDrivers
	)

	$result = New-ModuleResult -ModuleName 'Module4-DriverManagement'

	try {
		$records = Get-PnPUtilDriverRecords
		$protectedSet = Get-ProtectedDriverInfSet
		$plan = Get-DriverDeduplicationPlan -DriverRecords $records -ProtectedInfSet $protectedSet

		$previewRows = foreach ($group in $plan) {
			[pscustomobject]@{
				HardwareId      = if ($group.HardwareId) { $group.HardwareId } else { $group.GroupKey }
				DriverToKeep    = $group.DriverToKeep.INFName
				DriversToRemove = ($group.DriversToRemove | ForEach-Object { $_.INFName }) -join ', '
				Reason          = $group.Reason
				InUseProtected  = $group.InUseProtected
			}
		}

		if ($previewRows.Count -eq 0) {
			Write-LogUtc -Message 'Driver deduplication found no duplicate groups.'
			$result.ChangesApplied += 'No duplicate drivers found.'
			$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
			return $result
		}

		$previewText = $previewRows | Format-Table -AutoSize | Out-String
		Write-Host $previewText
		Write-LogUtc -Message "Driver preview table generated.`n$previewText"
		$result.ChangesApplied += 'Driver preview table generated.'

		if ($PreviewDriversToRemove -and -not $RemoveDuplicateDrivers) {
			Write-LogUtc -Message 'Preview mode only requested; no driver changes will be made.'
			$result.Warnings += 'Preview mode active: no changes applied.'
			$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
			return $result
		}

		if (-not $RemoveDuplicateDrivers) {
			Write-LogUtc -Message 'Driver removal switch not enabled; module completed in analysis mode.'
			$result.Warnings += 'RemoveDuplicateDrivers not set; no removals performed.'
			$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
			return $result
		}

		$driverRemovalRoot = Join-Path -Path $BackupRootPath -ChildPath 'DriverRemovals'
		if (-not (Test-Path -Path $driverRemovalRoot)) {
			if (-not $DryRun) {
				New-Item -Path $driverRemovalRoot -ItemType Directory -Force | Out-Null
			}
		}

		foreach ($group in $plan) {
			foreach ($candidate in $group.DriversToRemove) {
				if ($protectedSet.Contains($candidate.INFName)) {
					Write-LogUtc -Message ("Protected driver skipped: {0}" -f $candidate.INFName) -Level 'WARN'
					$result.Warnings += ("Protected driver skipped: {0}" -f $candidate.INFName)
					continue
				}

				$backupDestination = Join-Path -Path $driverRemovalRoot -ChildPath $candidate.INFName
				$manifestEntry = [pscustomobject]@{
					TimestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
					HardwareId        = $group.HardwareId
					DeviceInstanceId  = $group.DeviceInstanceId
					INFName           = $candidate.INFName
					KeepINF           = $group.DriverToKeep.INFName
					BackupDestination = $backupDestination
					Reason            = $group.Reason
					Action            = 'PlannedRemoval'
				}

				if ($DryRun) {
					Write-LogUtc -Message ("[DryRun] Would export and remove duplicate driver: {0}" -f $candidate.INFName) -Level 'WARN'
					continue
				}

				if ($PSCmdlet.ShouldProcess($candidate.INFName, 'Export duplicate driver backup')) {
					$exportOut = & pnputil.exe /export-driver $candidate.INFName $backupDestination 2>&1
					if ($LASTEXITCODE -ne 0) {
						throw ("Driver export failed for {0}. Output: {1}" -f $candidate.INFName, ($exportOut -join ' '))
					}
					Write-LogUtc -Message ("Driver backup export completed: {0} -> {1}" -f $candidate.INFName, $backupDestination)
				}

				Add-DriverRemovalManifestEntry -Entry $manifestEntry

				$confirm = Request-StandardConfirmation -Message ("Remove duplicate driver {0} (keep {1})?" -f $candidate.INFName, $group.DriverToKeep.INFName)
				if (-not $confirm) {
					Write-LogUtc -Message ("Operator skipped removal for driver: {0}" -f $candidate.INFName) -Level 'WARN'
					$result.Warnings += ("Removal skipped by operator: {0}" -f $candidate.INFName)
					continue
				}

				if ($PSCmdlet.ShouldProcess($candidate.INFName, 'Delete duplicate driver package')) {
					$deleteOut = & pnputil.exe /delete-driver $candidate.INFName /uninstall /force 2>&1
					if ($LASTEXITCODE -ne 0) {
						throw ("Driver deletion failed for {0}. Output: {1}" -f $candidate.INFName, ($deleteOut -join ' '))
					}
					Write-LogUtc -Message ("Driver removed: {0}" -f $candidate.INFName)
				}

				$deviceError = $false
				if ($group.DeviceInstanceId) {
					$postDevice = Get-PnpDevice -InstanceId $group.DeviceInstanceId -ErrorAction SilentlyContinue
					if ($postDevice -and $postDevice.Status -notin @('OK', 'Unknown')) {
						$deviceError = $true
					}
				}

				if ($deviceError) {
					Write-LogUtc -Message ("Post-removal device issue detected for {0}; starting rollback." -f $candidate.INFName) -Level 'ERROR'
					$exportedInf = Get-ChildItem -Path $backupDestination -Recurse -Filter '*.inf' -ErrorAction SilentlyContinue | Select-Object -First 1
					if (-not $exportedInf) {
						throw ("Rollback failed for {0}: no exported INF found in backup." -f $candidate.INFName)
					}

					$rollbackOut = & pnputil.exe /add-driver $exportedInf.FullName /install 2>&1
					if ($LASTEXITCODE -ne 0) {
						throw ("Rollback add-driver failed for {0}. Output: {1}" -f $candidate.INFName, ($rollbackOut -join ' '))
					}

					Write-LogUtc -Message ("Rollback completed for driver: {0}" -f $candidate.INFName) -Level 'WARN'
					$result.RollbackSteps += ("Re-added {0} from {1}" -f $candidate.INFName, $exportedInf.FullName)
					$result.Warnings += ("Driver {0} removed then rolled back due to device status." -f $candidate.INFName)
				}
				else {
					$result.ChangesApplied += ("Driver removed: {0}" -f $candidate.INFName)
				}
			}
		}

		Write-LogUtc -Message 'Module 4 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 4 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 4

#region Orchestration (Chunks 1-4)

try {
	Initialize-ExecutionContext -LogPath $LogPath -BackupPath $BackupPath

	$script:AllModuleResults = @()

	$module1Result = Invoke-Module1EnvironmentAndHardwareDetection -IgnoreOSCheck:$IgnoreOSCheck
	$script:AllModuleResults += $module1Result
	if (-not $module1Result.Success) {
		throw ('Stopping because Module 1 failed: {0}' -f ($module1Result.Errors -join '; '))
	}
	$script:HardwareProfile = $module1Result.HardwareProfile
	Write-LogUtc -Message 'Script closure policy set: DISM/SFC will execute only in final module at end of script.'

	$module2Result = Invoke-Module2PrechecksAndBackups -HardwareProfile $script:HardwareProfile -SkipRestorePoint:$SkipRestorePoint
	$script:AllModuleResults += $module2Result
	if (-not $module2Result.Success) {
		throw ('Stopping because Module 2 failed: {0}' -f ($module2Result.Errors -join '; '))
	}
	$script:BackupManifestPath = $module2Result.BackupManifestPath
	$script:BackupRootPath = $module2Result.BackupRootPath
	Write-LogUtc -Message 'Closure guard remains active: DISM/SFC execution is reserved for final module only.'

	$module3Result = Invoke-Module3SafeCleanup -HardwareProfile $script:HardwareProfile -BackupRootPath $script:BackupRootPath -CleanupAgeDays $CleanupAgeDays
	$script:AllModuleResults += $module3Result
	if (-not $module3Result.Success) {
		throw ('Stopping because Module 3 failed: {0}' -f ($module3Result.Errors -join '; '))
	}
	Write-LogUtc -Message 'Closure guard retained: DISM/SFC will run only at script end in Module 7.'

	$module4Result = Invoke-Module4DriverManagement -HardwareProfile $script:HardwareProfile -BackupRootPath $script:BackupRootPath -PreviewDriversToRemove:$PreviewDriversToRemove -RemoveDuplicateDrivers:$RemoveDuplicateDrivers
	$script:AllModuleResults += $module4Result
	if (-not $module4Result.Success) {
		throw ('Stopping because Module 4 failed: {0}' -f ($module4Result.Errors -join '; '))
	}
	Write-LogUtc -Message 'Module 4 finished. DISM/SFC still deferred to final closure module.'
}
catch {
	Write-Error $_.Exception.Message
	if ($script:LogFilePath) {
		Write-LogUtc -Message ('Fatal orchestration error in modules 1-4: {0}' -f $_.Exception.Message) -Level 'ERROR'
	}
	throw
}

#endregion Orchestration (Chunks 1-4)

#region Module 5 Helpers

function Get-OptionalServicesMap {
<#
.SYNOPSIS
Returns embedded optional-services allowlist.

.DESCRIPTION
Defines services eligible for startup optimization. Services not in this map are never modified.

.EXAMPLE
$map = Get-OptionalServicesMap
#>
	[CmdletBinding()]
	param()

	return @{
		'DiagTrack'   = 'Manual'
		'WerSvc'      = 'Manual'
		'MapsBroker'  = 'Manual'
		'PcaSvc'      = 'Manual'
		'RemoteRegistry' = 'Manual'
		'WSearch'     = 'Automatic'
	}
}

function Get-ServiceStartModeMap {
<#
.SYNOPSIS
Builds current service startup mode map.

.DESCRIPTION
Uses CIM service metadata to capture startup mode for rollback/reporting.

.EXAMPLE
$modes = Get-ServiceStartModeMap
#>
	[CmdletBinding()]
	param()

	$map = @{}
	$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
		Select-Object Name, StartMode, State

	foreach ($svc in $services) {
		$map[$svc.Name] = [pscustomobject]@{
			StartMode = $svc.StartMode
			State     = $svc.State
		}
	}

	return $map
}

function Test-ServiceSafeToModify {
<#
.SYNOPSIS
Validates that service is safe to modify.

.DESCRIPTION
Prevents changing startup type for services that are dependencies of currently running services.

.PARAMETER Name
Service name.

.EXAMPLE
$ok = Test-ServiceSafeToModify -Name 'DiagTrack'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Name
	)

	try {
		$runningDependents = Get-Service | Where-Object {
			$_.Status -eq 'Running' -and ($_.ServicesDependedOn | Where-Object { $_.Name -eq $Name })
		}
		return ($runningDependents.Count -eq 0)
	}
	catch {
		Write-LogUtc -Message ("Dependency inspection failed for service {0}: {1}" -f $Name, $_.Exception.Message) -Level 'WARN'
		return $false
	}
}

function Convert-ToServiceStartupType {
<#
.SYNOPSIS
Converts startup mode text to Set-Service accepted values.

.PARAMETER StartMode
Win32_Service StartMode text.

.EXAMPLE
$type = Convert-ToServiceStartupType -StartMode 'Auto'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$StartMode
	)

	switch ($StartMode.ToLowerInvariant()) {
		'auto'      { return 'Automatic' }
		'automatic' { return 'Automatic' }
		'manual'    { return 'Manual' }
		'disabled'  { return 'Disabled' }
		default     { return 'Manual' }
	}
}

function Set-ServiceStartupTypeSafe {
<#
.SYNOPSIS
Sets service startup type with safety checks.

.DESCRIPTION
Applies startup change only when service is allowlisted, safe by dependency check, and confirmed.

.PARAMETER ServiceName
Service short name.

.PARAMETER TargetStartupType
Target startup type for Set-Service.

.PARAMETER BaselineMap
Original service startup map used for rollback capture.

.EXAMPLE
Set-ServiceStartupTypeSafe -ServiceName 'DiagTrack' -TargetStartupType 'Manual' -BaselineMap $baseline
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[string]$ServiceName,

		[Parameter(Mandatory = $true)]
		[string]$TargetStartupType,

		[Parameter(Mandatory = $true)]
		[hashtable]$BaselineMap
	)

	if (-not (Test-ServiceSafeToModify -Name $ServiceName)) {
		Write-LogUtc -Message ("Service startup change skipped due to dependency safety gate: {0}" -f $ServiceName) -Level 'WARN'
		return [pscustomobject]@{ Changed = $false; Reason = 'Dependency safety gate'; Service = $ServiceName }
	}

	$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
	if (-not $service) {
		Write-LogUtc -Message ("Service not found; skipped: {0}" -f $ServiceName) -Level 'WARN'
		return [pscustomobject]@{ Changed = $false; Reason = 'Service missing'; Service = $ServiceName }
	}

	$currentStartMode = 'Unknown'
	if ($BaselineMap.ContainsKey($ServiceName)) {
		$currentStartMode = [string]$BaselineMap[$ServiceName].StartMode
	}

	if ((Convert-ToServiceStartupType -StartMode $currentStartMode) -eq $TargetStartupType) {
		Write-LogUtc -Message ("Service startup already set; skipped: {0}={1}" -f $ServiceName, $TargetStartupType)
		return [pscustomobject]@{ Changed = $false; Reason = 'Already set'; Service = $ServiceName }
	}

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would set service startup: {0} -> {1}" -f $ServiceName, $TargetStartupType) -Level 'WARN'
		return [pscustomobject]@{ Changed = $false; Reason = 'DryRun'; Service = $ServiceName }
	}

	if ($PSCmdlet.ShouldProcess($ServiceName, ("Set startup type to {0}" -f $TargetStartupType))) {
		Set-Service -Name $ServiceName -StartupType $TargetStartupType -ErrorAction Stop
		Write-LogUtc -Message ("Service startup changed: {0} {1} -> {2}" -f $ServiceName, $currentStartMode, $TargetStartupType)
		return [pscustomobject]@{ Changed = $true; Reason = 'Updated'; Service = $ServiceName; Old = $currentStartMode; New = $TargetStartupType }
	}

	return [pscustomobject]@{ Changed = $false; Reason = 'Not approved'; Service = $ServiceName }
}

function Get-StartupItems {
<#
.SYNOPSIS
Gets startup entries from registry and scheduled tasks.

.DESCRIPTION
Builds startup items for preview and optional disable workflow.

.EXAMPLE
$items = Get-StartupItems
#>
	[CmdletBinding()]
	param()

	$items = @()

	$runPaths = @(
		'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
		'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
	)

	foreach ($path in $runPaths) {
		if (-not (Test-Path -Path $path)) { continue }
		$props = Get-ItemProperty -Path $path
		foreach ($p in $props.PSObject.Properties) {
			if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
			$items += [pscustomobject]@{
				Type     = 'RegistryRun'
				Name     = $p.Name
				Value    = [string]$p.Value
				Location = $path
			}
		}
	}

	$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
		$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\Windows\\*'
	}

	foreach ($t in $tasks) {
		$items += [pscustomobject]@{
			Type     = 'ScheduledTask'
			Name     = $t.TaskName
			Value    = $t.State
			Location = $t.TaskPath
		}
	}

	return $items
}

function Disable-StartupItemSafe {
<#
.SYNOPSIS
Disables startup item without deleting it.

.DESCRIPTION
For registry Run items, prefixes value with "DISABLED_BY_OPTIMIZEWINDOWS10::" for reversible disable.
For scheduled tasks, disables task via Disable-ScheduledTask.

.PARAMETER Item
Startup item object from Get-StartupItems.

.EXAMPLE
Disable-StartupItemSafe -Item $item
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Item
	)

	$prefix = 'DISABLED_BY_OPTIMIZEWINDOWS10::'

	if ($Item.Type -eq 'RegistryRun') {
		if ($Item.Value -like "$prefix*") {
			Write-LogUtc -Message ("Startup registry item already disabled: {0}" -f $Item.Name)
			return [pscustomobject]@{ Changed = $false; Reason = 'Already disabled'; Item = $Item.Name }
		}

		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would disable startup registry item: {0} ({1})" -f $Item.Name, $Item.Location) -Level 'WARN'
			return [pscustomobject]@{ Changed = $false; Reason = 'DryRun'; Item = $Item.Name }
		}

		if ($PSCmdlet.ShouldProcess($Item.Name, 'Disable startup registry item')) {
			Set-ItemProperty -Path $Item.Location -Name $Item.Name -Value ("{0}{1}" -f $prefix, $Item.Value) -ErrorAction Stop
			Write-LogUtc -Message ("Startup registry item disabled: {0} at {1}" -f $Item.Name, $Item.Location)
			return [pscustomobject]@{ Changed = $true; Reason = 'Disabled'; Item = $Item.Name }
		}
	}

	if ($Item.Type -eq 'ScheduledTask') {
		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would disable scheduled task startup item: {0} ({1})" -f $Item.Name, $Item.Location) -Level 'WARN'
			return [pscustomobject]@{ Changed = $false; Reason = 'DryRun'; Item = $Item.Name }
		}

		if ($PSCmdlet.ShouldProcess($Item.Name, 'Disable scheduled task')) {
			Disable-ScheduledTask -TaskName $Item.Name -TaskPath $Item.Location -ErrorAction Stop | Out-Null
			Write-LogUtc -Message ("Scheduled task disabled: {0}{1}" -f $Item.Location, $Item.Name)
			return [pscustomobject]@{ Changed = $true; Reason = 'Disabled'; Item = $Item.Name }
		}
	}

	return [pscustomobject]@{ Changed = $false; Reason = 'Unsupported type'; Item = $Item.Name }
}

#endregion Module 5 Helpers

#region Module 5

function Invoke-Module5ServicesAndStartupOptimization {
<#
.SYNOPSIS
Runs Module 5 service and startup optimization.

.DESCRIPTION
Applies allowlist-only, dependency-safe service startup tuning and optional startup item disabling.
Never deletes services or startup entries and records baseline rollback metadata.

.PARAMETER HardwareProfile
Hardware profile from Module 1.

.EXAMPLE
$module5 = Invoke-Module5ServicesAndStartupOptimization -HardwareProfile $script:HardwareProfile
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile
	)

	$result = New-ModuleResult -ModuleName 'Module5-ServicesAndStartupOptimization'

	try {
		$allowMap = Get-OptionalServicesMap
		$baseline = Get-ServiceStartModeMap

		$servicePreview = @()
		foreach ($serviceName in $allowMap.Keys) {
			$oldMode = if ($baseline.ContainsKey($serviceName)) { [string]$baseline[$serviceName].StartMode } else { 'Missing' }
			$servicePreview += [pscustomobject]@{
				ServiceName = $serviceName
				Current     = $oldMode
				Target      = [string]$allowMap[$serviceName]
				CanModify   = (Test-ServiceSafeToModify -Name $serviceName)
			}
		}

		$startupItems = Get-StartupItems
		$startupPreview = $startupItems | Select-Object Type, Name, Location

		Write-Host ($servicePreview | Format-Table -AutoSize | Out-String)
		Write-Host ($startupPreview | Format-Table -AutoSize | Out-String)
		Write-LogUtc -Message "Module 5 preview generated for services and startup items."

		$proceed = $true
		if (-not $AutoApprove) {
			$proceed = (Read-Host 'Apply Module 5 service/startup optimizations? Type Y to continue') -match '^(Y|y)$'
		}

		if (-not $proceed) {
			$result.Warnings += 'Module 5 changes skipped by operator.'
			Write-LogUtc -Message 'Module 5 changes skipped by operator.' -Level 'WARN'
			$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
			return $result
		}

		foreach ($svc in $servicePreview) {
			if ($svc.Current -eq 'Missing') {
				$result.Warnings += ("Service missing, skipped: {0}" -f $svc.ServiceName)
				continue
			}

			$setResult = Set-ServiceStartupTypeSafe -ServiceName $svc.ServiceName -TargetStartupType $svc.Target -BaselineMap $baseline
			if ($setResult.Changed) {
				$result.ChangesApplied += ("Service startup updated: {0} -> {1}" -f $svc.ServiceName, $svc.Target)
				$result.RollbackSteps += ("Restore service {0} startup mode to {1}" -f $svc.ServiceName, $svc.Current)
			}
			elseif ($setResult.Reason -ne 'Already set') {
				$result.Warnings += ("Service unchanged: {0} ({1})" -f $svc.ServiceName, $setResult.Reason)
			}
		}

		foreach ($item in $startupItems) {
			$disableResult = Disable-StartupItemSafe -Item $item
			if ($disableResult.Changed) {
				$result.ChangesApplied += ("Startup item disabled: {0} ({1})" -f $item.Name, $item.Type)
				if ($item.Type -eq 'RegistryRun') {
					$result.RollbackSteps += ("Remove DISABLED_BY_OPTIMIZEWINDOWS10:: prefix from startup item {0} at {1}" -f $item.Name, $item.Location)
				}
				elseif ($item.Type -eq 'ScheduledTask') {
					$result.RollbackSteps += ("Re-enable scheduled task {0}{1}" -f $item.Location, $item.Name)
				}
			}
		}

		Write-LogUtc -Message 'Module 5 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 5 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 5

#region Orchestration (Chunk 5)

try {
	if (-not $script:HardwareProfile) {
		throw 'Module 1 output missing. HardwareProfile was not initialized.'
	}

	$module5Result = Invoke-Module5ServicesAndStartupOptimization -HardwareProfile $script:HardwareProfile
	$script:AllModuleResults += $module5Result

	if (-not $module5Result.Success) {
		throw ('Stopping because Module 5 failed: {0}' -f ($module5Result.Errors -join '; '))
	}

	Write-LogUtc -Message 'Module 5 finished. DISM/SFC remain deferred to Module 7 final closure.'
}
catch {
	Write-Error $_.Exception.Message
	if ($script:LogFilePath) {
		Write-LogUtc -Message ('Fatal orchestration error in module 5: {0}' -f $_.Exception.Message) -Level 'ERROR'
	}
	throw
}

#endregion Orchestration (Chunk 5)

#region Module 6 Helpers

function Get-ActivePowerScheme {
<#
.SYNOPSIS
Gets active power scheme GUID and name.

.DESCRIPTION
Parses powercfg /getactivescheme output.

.EXAMPLE
$active = Get-ActivePowerScheme
#>
	[CmdletBinding()]
	param()

	$out = & powercfg.exe /getactivescheme 2>&1
	$text = ($out -join ' ')
	if ($text -match '([A-Fa-f0-9\-]{36})\s*\(([^\)]+)\)') {
		return [pscustomobject]@{ Guid = $matches[1]; Name = $matches[2] }
	}

	return [pscustomobject]@{ Guid = $null; Name = 'Unknown' }
}

function Get-OptimizePowerPlanGuid {
	[CmdletBinding()]
	param()

	$out = & powercfg.exe /l 2>&1
	foreach ($line in $out) {
		if ($line -match 'Power Scheme GUID:\s*([A-Fa-f0-9\-]{36})\s*\((Optimize-Windows10-Performance)\)') {
			return $matches[1]
		}
	}

	return $null
}

function Ensure-OptimizePowerPlan {
<#
.SYNOPSIS
Creates Optimize-Windows10-Performance power plan if missing.

.DESCRIPTION
Duplicates High performance plan and renames it. Does not set active plan.

.EXAMPLE
$guid = Ensure-OptimizePowerPlan
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param()

	$existing = Get-OptimizePowerPlanGuid
	if ($existing) {
		Write-LogUtc -Message ("Optimize power plan already exists: {0}" -f $existing)
		return $existing
	}

	if ($DryRun) {
		Write-LogUtc -Message '[DryRun] Would create Optimize-Windows10-Performance power plan.' -Level 'WARN'
		return 'DRYRUN-PLAN-GUID'
	}

	if ($PSCmdlet.ShouldProcess('Power plan catalog', 'Create Optimize-Windows10-Performance plan')) {
		$dup = & powercfg.exe -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1
		$dupText = ($dup -join ' ')
		if ($dupText -notmatch '([A-Fa-f0-9\-]{36})') {
			throw 'Failed to duplicate High performance power plan.'
		}

		$newGuid = $matches[1]
		& powercfg.exe -changename $newGuid 'Optimize-Windows10-Performance' | Out-Null
		Write-LogUtc -Message ("Created Optimize-Windows10-Performance power plan: {0}" -f $newGuid)
		return $newGuid
	}

	return $null
}

function Get-PagefileRecommendation {
<#
.SYNOPSIS
Builds pagefile recommendation based on RAM and storage type.

.DESCRIPTION
Recommends system-managed on SSD. On HDD, recommends bounded range of 1x-1.5x RAM.

.PARAMETER HardwareProfile
Hardware profile from Module 1.

.EXAMPLE
$rec = Get-PagefileRecommendation -HardwareProfile $script:HardwareProfile
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile
	)

	$systemDrive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
	$systemType = 'HDD'
	if ($HardwareProfile.StorageType.ContainsKey($systemDrive)) {
		$systemType = [string]$HardwareProfile.StorageType[$systemDrive]
	}

	$ramGb = [double]$HardwareProfile.TotalRAMgb
	$ramMb = [math]::Round($ramGb * 1024)

	if ($systemType -eq 'SSD') {
		return [pscustomobject]@{
			StorageType = 'SSD'
			Mode        = 'SystemManaged'
			InitialMB   = $null
			MaximumMB   = $null
			Note        = 'System-managed pagefile recommended on SSD.'
		}
	}

	$initial = [int]$ramMb
	$maximum = [int]([math]::Round($ramMb * 1.5))

	return [pscustomobject]@{
		StorageType = 'HDD'
		Mode        = 'Custom'
		InitialMB   = $initial
		MaximumMB   = $maximum
		Note        = 'For HDD, use bounded pagefile between 1x and 1.5x RAM.'
	}
}

function Set-PagefileConfiguration {
<#
.SYNOPSIS
Applies pagefile setting recommendation.

.DESCRIPTION
Switches to system-managed or custom pagefile based on recommendation.

.PARAMETER Recommendation
Recommendation object from Get-PagefileRecommendation.

.EXAMPLE
Set-PagefileConfiguration -Recommendation $rec
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Recommendation
	)

	$computer = Get-CimInstance -ClassName Win32_ComputerSystem
	$current = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would apply pagefile mode: {0}" -f $Recommendation.Mode) -Level 'WARN'
		return
	}

	if ($Recommendation.Mode -eq 'SystemManaged') {
		if ($PSCmdlet.ShouldProcess('Pagefile', 'Enable automatic managed pagefile')) {
			Set-CimInstance -InputObject $computer -Property @{ AutomaticManagedPagefile = $true } | Out-Null
			Write-LogUtc -Message 'Set pagefile mode to system-managed.'
		}
		return
	}

	if ($PSCmdlet.ShouldProcess('Pagefile', 'Set custom pagefile size')) {
		Set-CimInstance -InputObject $computer -Property @{ AutomaticManagedPagefile = $false } | Out-Null

		$pagePath = "$($env:SystemDrive)\\pagefile.sys"
		if ($current) {
			foreach ($pf in $current) {
				Remove-CimInstance -InputObject $pf -ErrorAction SilentlyContinue
			}
		}

		New-CimInstance -ClassName Win32_PageFileSetting -Property @{
			Name        = $pagePath
			InitialSize = [int]$Recommendation.InitialMB
			MaximumSize = [int]$Recommendation.MaximumMB
		} | Out-Null

		Write-LogUtc -Message ("Set custom pagefile: InitialMB={0}, MaximumMB={1}" -f $Recommendation.InitialMB, $Recommendation.MaximumMB)
	}
}

function Set-VisualEffectsPresetSafe {
<#
.SYNOPSIS
Applies visual effects preset.

.DESCRIPTION
Balanced leaves defaults untouched. Performance and MaxPerformance apply VisualFXSetting values.

.PARAMETER Preset
Balanced | Performance | MaxPerformance.

.EXAMPLE
Set-VisualEffectsPresetSafe -Preset $VisualEffectsPreset
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateSet('Balanced', 'Performance', 'MaxPerformance')]
		[string]$Preset
	)

	if ($Preset -eq 'Balanced') {
		Write-LogUtc -Message 'Balanced visual effects preset selected; no forced change applied.'
		return
	}

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would apply visual effects preset: {0}" -f $Preset) -Level 'WARN'
		return
	}

	$targetValue = if ($Preset -eq 'Performance') { 2 } else { 2 }
	if ($PSCmdlet.ShouldProcess('HKCU VisualEffects', ("Apply visual effects preset: {0}" -f $Preset))) {
		New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Force | Out-Null
		Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Type DWord -Value $targetValue
		Write-LogUtc -Message ("Visual effects preset applied: {0}" -f $Preset)
	}
}

function Set-SysMainByStorageType {
<#
.SYNOPSIS
Configures SysMain based on storage type.

.DESCRIPTION
Disable only on SSD and only with confirmation. Keep enabled on HDD.

.PARAMETER HardwareProfile
Hardware profile object.

.EXAMPLE
Set-SysMainByStorageType -HardwareProfile $script:HardwareProfile
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile
	)

	$systemDrive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
	$storageType = if ($HardwareProfile.StorageType.ContainsKey($systemDrive)) { [string]$HardwareProfile.StorageType[$systemDrive] } else { 'HDD' }

	$svc = Get-Service -Name 'SysMain' -ErrorAction SilentlyContinue
	if (-not $svc) {
		Write-LogUtc -Message 'SysMain service not found; skipping.' -Level 'WARN'
		return [pscustomobject]@{ Changed = $false; Reason = 'Missing' }
	}

	if ($storageType -eq 'HDD') {
		Write-LogUtc -Message 'Storage is HDD; SysMain remains enabled by policy.'
		return [pscustomobject]@{ Changed = $false; Reason = 'HDD keep enabled' }
	}

	$confirm = Request-StandardConfirmation -Message 'Storage detected as SSD. Disable SysMain?'
	if (-not $confirm) {
		Write-LogUtc -Message 'SysMain disable declined by operator.'
		return [pscustomobject]@{ Changed = $false; Reason = 'Declined' }
	}

	if ($DryRun) {
		Write-LogUtc -Message '[DryRun] Would disable SysMain service on SSD.' -Level 'WARN'
		return [pscustomobject]@{ Changed = $false; Reason = 'DryRun' }
	}

	if ($PSCmdlet.ShouldProcess('SysMain', 'Disable service for SSD optimization')) {
		Stop-Service -Name 'SysMain' -Force -ErrorAction SilentlyContinue
		Set-Service -Name 'SysMain' -StartupType Disabled -ErrorAction Stop
		Write-LogUtc -Message 'SysMain disabled for SSD profile.'
		return [pscustomobject]@{ Changed = $true; Reason = 'DisabledOnSSD' }
	}

	return [pscustomobject]@{ Changed = $false; Reason = 'Not approved' }
}

function Set-HeavyTasksScheduleWindow {
<#
.SYNOPSIS
Reschedules selected heavy tasks to 02:00-04:00.

.DESCRIPTION
Updates start boundaries for known heavy tasks when operator confirms.

.EXAMPLE
Set-HeavyTasksScheduleWindow
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param()

	$targets = @(
		@{ TaskPath='\\Microsoft\\Windows\\Defrag\\'; TaskName='ScheduledDefrag'; NewTime='02:30' },
		@{ TaskPath='\\Microsoft\\Windows\\Customer Experience Improvement Program\\'; TaskName='Consolidator'; NewTime='03:00' }
	)

	$confirm = Request-StandardConfirmation -Message 'Reschedule heavy maintenance tasks into 02:00-04:00 window?'
	if (-not $confirm) {
		Write-LogUtc -Message 'Heavy task reschedule declined by operator.'
		return @()
	}

	$changes = @()
	foreach ($t in $targets) {
		try {
			$task = Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue
			if (-not $task) { continue }

			if ($DryRun) {
				Write-LogUtc -Message ("[DryRun] Would reschedule task {0}{1} to {2}" -f $t.TaskPath, $t.TaskName, $t.NewTime) -Level 'WARN'
				$changes += ("{0}{1} -> {2}" -f $t.TaskPath, $t.TaskName, $t.NewTime)
				continue
			}

			if ($PSCmdlet.ShouldProcess(($t.TaskPath + $t.TaskName), ("Set task start time to {0}" -f $t.NewTime))) {
				$action = (Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName).Actions
				$trigger = New-ScheduledTaskTrigger -Daily -At $t.NewTime
				$principal = (Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName).Principal
				$settings = (Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName).Settings
				Register-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
				Write-LogUtc -Message ("Rescheduled task {0}{1} to {2}" -f $t.TaskPath, $t.TaskName, $t.NewTime)
				$changes += ("{0}{1} -> {2}" -f $t.TaskPath, $t.TaskName, $t.NewTime)
			}
		}
		catch {
			Write-LogUtc -Message ("Failed to reschedule task {0}{1}: {2}" -f $t.TaskPath, $t.TaskName, $_.Exception.Message) -Level 'WARN'
		}
	}

	return $changes
}

#endregion Module 6 Helpers

#region Module 6

function Invoke-Module6PerformanceTuning {
<#
.SYNOPSIS
Runs Module 6 performance tuning.

.DESCRIPTION
Applies hardware-aware tuning for power plan, pagefile, visual effects, SysMain, and heavy task scheduling.
Each action is independently confirmable and logged.

.PARAMETER HardwareProfile
Hardware profile from Module 1.

.PARAMETER VisualEffectsPreset
Balanced | Performance | MaxPerformance.

.EXAMPLE
$module6 = Invoke-Module6PerformanceTuning -HardwareProfile $script:HardwareProfile -VisualEffectsPreset $VisualEffectsPreset
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$HardwareProfile,

		[Parameter(Mandatory = $true)]
		[ValidateSet('Balanced', 'Performance', 'MaxPerformance')]
		[string]$VisualEffectsPreset
	)

	$result = New-ModuleResult -ModuleName 'Module6-PerformanceTuning'

	try {
		$activeBefore = Get-ActivePowerScheme
		$result.RollbackSteps += ("Restore active power scheme to {0} ({1})" -f $activeBefore.Name, $activeBefore.Guid)

		$createPlan = Request-StandardConfirmation -Message 'Create Optimize-Windows10-Performance power plan?'
		$planGuid = $null
		if ($createPlan) {
			$planGuid = Ensure-OptimizePowerPlan
			if ($planGuid) {
				$result.ChangesApplied += ("Optimize power plan available: {0}" -f $planGuid)
			}
		}

		if ($planGuid -and $planGuid -ne 'DRYRUN-PLAN-GUID') {
			$switchPlan = Request-StandardConfirmation -Message 'Switch active power plan to Optimize-Windows10-Performance?'
			if ($switchPlan) {
				if ($DryRun) {
					Write-LogUtc -Message ("[DryRun] Would set active power plan: {0}" -f $planGuid) -Level 'WARN'
				}
				elseif ($PSCmdlet.ShouldProcess($planGuid, 'Set active power scheme')) {
					& powercfg.exe /setactive $planGuid | Out-Null
					Write-LogUtc -Message ("Active power scheme set to: {0}" -f $planGuid)
					$result.ChangesApplied += 'Active power scheme updated.'
				}
			}
		}

		$pageRec = Get-PagefileRecommendation -HardwareProfile $HardwareProfile
		Write-Host ("Pagefile recommendation: Mode={0}; InitialMB={1}; MaximumMB={2}; Note={3}" -f $pageRec.Mode, $pageRec.InitialMB, $pageRec.MaximumMB, $pageRec.Note)
		$pageApply = Request-StandardConfirmation -Message 'Apply pagefile recommendation?'
		if ($pageApply) {
			Set-PagefileConfiguration -Recommendation $pageRec
			$result.ChangesApplied += ("Pagefile configuration applied: {0}" -f $pageRec.Mode)
			$result.RollbackSteps += 'Restore previous pagefile settings from baseline snapshots.'
		}

		Set-VisualEffectsPresetSafe -Preset $VisualEffectsPreset
		if ($VisualEffectsPreset -ne 'Balanced') {
			$result.ChangesApplied += ("Visual effects preset applied: {0}" -f $VisualEffectsPreset)
			$result.RollbackSteps += 'Set visual effects back to Windows default (Balanced).'
		}

		$sysMainResult = Set-SysMainByStorageType -HardwareProfile $HardwareProfile
		if ($sysMainResult.Changed) {
			$result.ChangesApplied += 'SysMain disabled for SSD profile.'
			$result.RollbackSteps += 'Re-enable SysMain and set startup type to Automatic.'
		}

		$taskChanges = Set-HeavyTasksScheduleWindow
		foreach ($c in $taskChanges) {
			$result.ChangesApplied += ("Task rescheduled: {0}" -f $c)
			$result.RollbackSteps += ("Restore original schedule for task: {0}" -f $c)
		}

		Write-LogUtc -Message 'Module 6 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 6 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 6

#region Orchestration (Chunk 6)

try {
	if (-not $script:HardwareProfile) {
		throw 'Module 1 output missing. HardwareProfile was not initialized.'
	}

	$module6Result = Invoke-Module6PerformanceTuning -HardwareProfile $script:HardwareProfile -VisualEffectsPreset $VisualEffectsPreset
	$script:AllModuleResults += $module6Result

	if (-not $module6Result.Success) {
		throw ('Stopping because Module 6 failed: {0}' -f ($module6Result.Errors -join '; '))
	}

	Write-LogUtc -Message 'Module 6 finished. DISM/SFC still locked to Module 7 as final closure stage.'
}
catch {
	Write-Error $_.Exception.Message
	if ($script:LogFilePath) {
		Write-LogUtc -Message ('Fatal orchestration error in module 6: {0}' -f $_.Exception.Message) -Level 'ERROR'
	}
	throw
}

#endregion Orchestration (Chunk 6)

#region Module 7 Helpers

function Invoke-LoggedExternalCommand {
<#
.SYNOPSIS
Runs external command and logs full output to timestamped file.

.DESCRIPTION
Executes command line tools, captures stdout/stderr, writes output to a dedicated log file,
and returns exit code and output path metadata.

.PARAMETER FilePath
Executable path.

.PARAMETER Arguments
Argument array.

.PARAMETER Label
Label used in log file naming.

.EXAMPLE
$run = Invoke-LoggedExternalCommand -FilePath 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/ScanHealth') -Label 'DISM_ScanHealth'
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$FilePath,

		[Parameter(Mandatory = $true)]
		[string[]]$Arguments,

		[Parameter(Mandatory = $true)]
		[string]$Label
	)

	$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
	$outputPath = Join-Path -Path $script:ResolvedLogPath -ChildPath ("{0}_{1}.log" -f $Label, $stamp)

	if ($DryRun) {
		Write-LogUtc -Message ("[DryRun] Would execute: {0} {1}" -f $FilePath, ($Arguments -join ' ')) -Level 'WARN'
		return [pscustomobject]@{
			Command    = $FilePath
			Arguments  = $Arguments
			ExitCode   = 0
			OutputPath = $outputPath
			OutputText = '[DryRun] No command executed.'
		}
	}

	$output = & $FilePath @Arguments 2>&1
	$exitCode = $LASTEXITCODE
	$outputText = ($output | Out-String)
	Set-Content -Path $outputPath -Value $outputText -Encoding UTF8

	Write-LogUtc -Message ("Command executed: {0} {1}; ExitCode={2}; Output={3}" -f $FilePath, ($Arguments -join ' '), $exitCode, $outputPath)

	return [pscustomobject]@{
		Command    = $FilePath
		Arguments  = $Arguments
		ExitCode   = $exitCode
		OutputPath = $outputPath
		OutputText = $outputText
	}
}

function Test-DismScanHealthIndicatesRepair {
<#
.SYNOPSIS
Determines whether DISM ScanHealth indicates corruption/issues.

.PARAMETER ScanOutputText
ScanHealth output text.

.EXAMPLE
$needs = Test-DismScanHealthIndicatesRepair -ScanOutputText $scan.OutputText
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$ScanOutputText
	)

	if ($ScanOutputText -match 'No component store corruption detected') { return $false }
	if ($ScanOutputText -match 'No corruption detected') { return $false }
	if ($ScanOutputText -match 'The component store is repairable') { return $true }
	if ($ScanOutputText -match 'corruption') { return $true }

	# Conservative default: if uncertain, treat as issue detected to preserve safety.
	return $true
}

#endregion Module 7 Helpers

#region Module 7

function Invoke-Module7SystemValidationAndRepair {
<#
.SYNOPSIS
Runs Module 7 system validation and repair sequence.

.DESCRIPTION
Runs fixed end-of-operations sequence:
1) DISM ScanHealth
2) Conditional DISM RestoreHealth (with one retry on failure)
3) SFC /scannow
4) DISM AnalyzeComponentStore

This module is closure-stage validation and must execute after modules 1-6 complete.

.EXAMPLE
$module7 = Invoke-Module7SystemValidationAndRepair
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param()

	$result = New-ModuleResult -ModuleName 'Module7-SystemValidationAndRepair'

	try {
		Write-LogUtc -Message 'Module 7 started as closure stage. DISM/SFC fixed sequence begins.'

		$scan = Invoke-LoggedExternalCommand -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/ScanHealth') -Label 'DISM_ScanHealth'
		$result.ChangesApplied += ("DISM ScanHealth log: {0}" -f $scan.OutputPath)
		$needsRestore = Test-DismScanHealthIndicatesRepair -ScanOutputText $scan.OutputText

		if ($needsRestore -or $Force) {
			$restore = Invoke-LoggedExternalCommand -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth') -Label 'DISM_RestoreHealth_Attempt1'
			$result.ChangesApplied += ("DISM RestoreHealth attempt1 log: {0}" -f $restore.OutputPath)

			if ($restore.ExitCode -ne 0) {
				Write-LogUtc -Message 'DISM RestoreHealth attempt 1 failed; retrying once.' -Level 'WARN'
				$restoreRetry = Invoke-LoggedExternalCommand -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth') -Label 'DISM_RestoreHealth_Attempt2'
				$result.ChangesApplied += ("DISM RestoreHealth attempt2 log: {0}" -f $restoreRetry.OutputPath)

				if ($restoreRetry.ExitCode -ne 0) {
					$result.Warnings += 'DISM RestoreHealth failed after one retry. Continuing to final reporting.'
					Write-LogUtc -Message 'DISM RestoreHealth failed after retry; continuing by policy.' -Level 'ERROR'
				}
			}
		}
		else {
			Write-LogUtc -Message 'DISM RestoreHealth skipped because ScanHealth found no issues and Force not set.'
		}

		$sfc = Invoke-LoggedExternalCommand -FilePath 'sfc.exe' -Arguments @('/scannow') -Label 'SFC_Scannow'
		$result.ChangesApplied += ("SFC log: {0}" -f $sfc.OutputPath)
		if ($sfc.ExitCode -notin @(0, 1)) {
			$result.Warnings += ("SFC returned non-success code {0}. Continuing by policy." -f $sfc.ExitCode)
			Write-LogUtc -Message ("SFC returned non-success code {0}; continuing by policy." -f $sfc.ExitCode) -Level 'ERROR'
		}

		$analyze = Invoke-LoggedExternalCommand -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore') -Label 'DISM_AnalyzeComponentStore'
		$result.ChangesApplied += ("DISM AnalyzeComponentStore log: {0}" -f $analyze.OutputPath)

		Write-LogUtc -Message 'Module 7 completed. Validation/repair closure sequence finished.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 7 failed unexpectedly: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 7

#region Orchestration (Chunk 7 Deferred)

$script:InvokeModule7AtClosure = $true
Write-LogUtc -Message 'Module 7 invocation deferred to final closure stage to keep DISM/SFC at script end.'

#endregion Orchestration (Chunk 7 Deferred)

#region Module 8 Helpers

function Get-DirectorySizeGB {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	if (-not (Test-Path -Path $Path)) { return 0.0 }
	$bytes = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	if (-not $bytes) { $bytes = 0 }
	return [math]::Round(($bytes / 1GB), 2)
}

function Remove-TrackedDefenderExclusions {
	[CmdletBinding()]
	param()

	if (-not $script:DefenderExclusionsAdded) { return }

	foreach ($path in @($script:DefenderExclusionsAdded)) {
		try {
			if ($DryRun) {
				Write-LogUtc -Message ("[DryRun] Would remove Defender exclusion: {0}" -f $path) -Level 'WARN'
				continue
			}

			Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
			Write-LogUtc -Message ("Removed Defender exclusion: {0}" -f $path)
		}
		catch {
			Write-LogUtc -Message ("Failed removing Defender exclusion {0}: {1}" -f $path, $_.Exception.Message) -Level 'ERROR'
		}
	}
}

function Get-ModuleResultByName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Name
	)

	return ($script:AllModuleResults | Where-Object { $_.ModuleName -eq $Name } | Select-Object -First 1)
}

function New-RollbackScriptContent {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$BackupRootPath
	)

	$driverBackupRoot = Join-Path -Path $BackupRootPath -ChildPath 'DriverRemovals'
	$registryRoot = Join-Path -Path $BackupRootPath -ChildPath 'Registry'

	@"
<#
.SYNOPSIS
Restore-Windows10-Backup.ps1 restores key artifacts from Optimize-Windows10 backups.
#>

[CmdletBinding(SupportsShouldProcess = `$true, ConfirmImpact = 'High')]
param()

`$ErrorActionPreference = 'Stop'

Write-Host 'Starting rollback restore operations...'

# Restore registry exports
if (Test-Path -Path '$registryRoot') {
	Get-ChildItem -Path '$registryRoot' -Filter '*.reg' -File -ErrorAction SilentlyContinue | ForEach-Object {
		Write-Host ("Importing registry backup: {0}" -f `$_.FullName)
		& reg.exe import `$_.FullName | Out-Null
	}
}

# Re-add backed up drivers
if (Test-Path -Path '$driverBackupRoot') {
	Get-ChildItem -Path '$driverBackupRoot' -Recurse -Filter '*.inf' -File -ErrorAction SilentlyContinue | ForEach-Object {
		Write-Host ("Re-adding driver: {0}" -f `$_.FullName)
		& pnputil.exe /add-driver `$_.FullName /install | Out-Null
	}
}

Write-Host 'Rollback command sequence completed.'
Write-Host 'If needed, use System Restore to the checkpoint created by Optimize-Windows10.'
"@
}

#endregion Module 8 Helpers

#region Module 8

function Invoke-Module8PostRunReportingAndRollback {
<#
.SYNOPSIS
Runs Module 8 post-run reporting and rollback artifact generation.

.DESCRIPTION
Builds final console/text report with deltas, warnings, validation outcomes, and writes
Restore-Windows10-Backup.ps1 into backup location.

.PARAMETER InitialHardwareProfile
Hardware profile from Module 1 for before/after comparison.

.PARAMETER BackupRootPath
Backup root generated during Module 2.
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$InitialHardwareProfile,

		[Parameter(Mandatory = $true)]
		[string]$BackupRootPath
	)

	$result = New-ModuleResult -ModuleName 'Module8-PostRunReportingAndRollback'

	try {
		$finalHardware = Get-HardwareProfile
		$module4 = Get-ModuleResultByName -Name 'Module4-DriverManagement'
		$module7 = Get-ModuleResultByName -Name 'Module7-SystemValidationAndRepair'

		$beforeAfter = @()
		foreach ($drive in $InitialHardwareProfile.FreeSpaceMap.Keys) {
			$before = [double]$InitialHardwareProfile.FreeSpaceMap[$drive]
			$after = if ($finalHardware.FreeSpaceMap.ContainsKey($drive)) { [double]$finalHardware.FreeSpaceMap[$drive] } else { $before }
			$delta = [math]::Round(($after - $before), 2)
			$beforeAfter += [pscustomobject]@{ Drive = $drive; BeforeGB = $before; AfterGB = $after; DeltaGB = $delta }
		}

		$driversRemoved = @()
		$driversProtected = @()
		if ($module4) {
			$driversRemoved = @($module4.ChangesApplied | Where-Object { $_ -like 'Driver removed:*' })
			$driversProtected = @($module4.Warnings | Where-Object { $_ -like 'Protected driver skipped:*' })
		}

		$backupSizeGb = Get-DirectorySizeGB -Path $BackupRootPath
		$reportPath = Join-Path -Path $script:ResolvedLogPath -ChildPath ("OptimizeWindows_FinalReport_{0}.txt" -f $script:RunId)

		$reportLines = @()
		$reportLines += 'Optimize-Windows10 Final Report'
		$reportLines += ('RunId: {0}' -f $script:RunId)
		$reportLines += ('GeneratedUtc: {0}' -f ((Get-Date).ToUniversalTime().ToString('o')))
		$reportLines += ''
		$reportLines += 'Disk Space Delta (GB)'
		foreach ($row in $beforeAfter) {
			$reportLines += ('{0}: Before={1}, After={2}, Delta={3}' -f $row.Drive, $row.BeforeGB, $row.AfterGB, $row.DeltaGB)
		}
		$reportLines += ''
		$reportLines += 'Driver Outcomes'
		if ($driversRemoved.Count -eq 0) { $reportLines += 'Drivers removed: None' } else { $reportLines += $driversRemoved }
		if ($driversProtected.Count -eq 0) { $reportLines += 'Drivers protected: None' } else { $reportLines += $driversProtected }
		$reportLines += ''
		$reportLines += 'Backup Summary'
		$reportLines += ('Backup root: {0}' -f $BackupRootPath)
		$reportLines += ('Approx backup size GB: {0}' -f $backupSizeGb)
		$reportLines += ''
		$reportLines += 'Validation Outcomes'
		if ($module7) {
			if ($module7.Warnings.Count -gt 0) {
				$reportLines += $module7.Warnings
			}
			else {
				$reportLines += 'DISM/SFC closure sequence completed with no warnings.'
			}
		}
		$reportLines += ''
		$reportLines += 'Vendor Driver Recommendation (guidance only)'
		$reportLines += '- GPU: NVIDIA GeForce / AMD Adrenalin / Intel Graphics download pages.'
		$reportLines += '- Chipset and storage: OEM support portal for your motherboard or device model.'
		$reportLines += '- No auto-download or auto-install was performed by this script.'
		$reportLines += ''
		$reportLines += 'Rollback Instructions'
		$reportLines += '1. Run Restore-Windows10-Backup.ps1 from backup folder in elevated PowerShell.'
		$reportLines += '2. Reboot and verify device state.'
		$reportLines += '3. If needed, use the System Restore point created at script start.'

		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would write final report: {0}" -f $reportPath) -Level 'WARN'
		}
		else {
			Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8
		}

		Write-Host ($reportLines -join [Environment]::NewLine)

		$rollbackScriptPath = Join-Path -Path $BackupRootPath -ChildPath 'Restore-Windows10-Backup.ps1'
		$rollbackContent = New-RollbackScriptContent -BackupRootPath $BackupRootPath
		if ($DryRun) {
			Write-LogUtc -Message ("[DryRun] Would write rollback script: {0}" -f $rollbackScriptPath) -Level 'WARN'
		}
		else {
			Set-Content -Path $rollbackScriptPath -Value $rollbackContent -Encoding UTF8
		}

		$result.ChangesApplied += ("Final report: {0}" -f $reportPath)
		$result.ChangesApplied += ("Rollback script: {0}" -f $rollbackScriptPath)
		$result.RollbackSteps += 'Use generated Restore-Windows10-Backup.ps1 for artifact restoration.'

		Write-LogUtc -Message 'Module 8 completed successfully.'
	}
	catch {
		$result.Success = $false
		$result.Errors += $_.Exception.Message
		Write-LogUtc -Message ("Module 8 failed: {0}" -f $_.Exception.Message) -Level 'ERROR'
	}
	finally {
		$result.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
	}

	return $result
}

#endregion Module 8

#region Final Closure Orchestration

$script:FinalExitCode = 0
try {
	if ($script:InvokeModule7AtClosure) {
		$module7Result = Invoke-Module7SystemValidationAndRepair
		$script:AllModuleResults += $module7Result

		if (-not $module7Result.Success) {
			Write-LogUtc -Message ('Module 7 reported failure state: {0}' -f ($module7Result.Errors -join '; ')) -Level 'ERROR'
		}
	}

	$module8Result = Invoke-Module8PostRunReportingAndRollback -InitialHardwareProfile $script:HardwareProfile -BackupRootPath $script:BackupRootPath
	$script:AllModuleResults += $module8Result

	if (-not $module8Result.Success) {
		$script:FinalExitCode = 1
		Write-LogUtc -Message ('Module 8 reported failure state: {0}' -f ($module8Result.Errors -join '; ')) -Level 'ERROR'
	}
}
catch {
	$script:FinalExitCode = 1
	Write-Error $_.Exception.Message
	if ($script:LogFilePath) {
		Write-LogUtc -Message ('Fatal final-closure orchestration error: {0}' -f $_.Exception.Message) -Level 'ERROR'
	}
}
finally {
	try {
		Remove-TrackedDefenderExclusions
	}
	catch {
		if ($script:LogFilePath) {
			Write-LogUtc -Message ('Final cleanup exclusion removal error: {0}' -f $_.Exception.Message) -Level 'ERROR'
		}
	}

	if ($script:LogFilePath) {
		Write-LogUtc -Message ('Script completed at UTC {0} with exit code {1}' -f ((Get-Date).ToUniversalTime().ToString('o')), $script:FinalExitCode)
	}

	if ($script:FinalExitCode -ne 0) {
		exit $script:FinalExitCode
	}
}

#endregion Final Closure Orchestration

# END OF SCRIPT - See <BackupPath>\Restore-Windows10-Backup.ps1
# for rollback instructions.
