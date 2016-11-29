
Function Get-DefenderDetails
{
Param(
	        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME
)

begin{
}

process{

Write-Verbose "Contacting $($computerName) to fetch defender info" 

if( Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue){

try{
$DefStatus = Get-WmiObject -Namespace ROOT\Microsoft\Windows\Defender -Class MSFT_MpComputerStatus -ComputerName $computerName -ErrorAction Stop


  <#$Sigupd1 = [Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.AntispywareSignatureLastUpdated)
  $Sigupd2 = [Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.AntivirusSignatureLastUpdated)
  $Sigupd3 = [Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.NISSignatureLastUpdated)

  $scanStart = [Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.FullScanStartTime)
  $scanEnd = [Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.FullScanEndTime)#>

	$OutputObj = New-Object -TypeName PSobject  
	$OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $DefStatus.PSComputerName
    $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerID -Value $DefStatus.ComputerID
    $OutputObj | Add-Member -MemberType NoteProperty -Name AntiMalwareServiceEnabled -Value $DefStatus.AMServiceEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name AntiSpywareEnabled -Value $DefStatus.AntispywareEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name AntivirusEnabled -Value $DefStatus.AntivirusEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name BehaviorMonitorEnabled -Value $DefStatus.BehaviorMonitorEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name IoavProtectionEnabled -Value $DefStatus.IoavProtectionEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name NISEnabled -Value $DefStatus.NISEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name OnAccessProtectionEnabled -Value $DefStatus.OnAccessProtectionEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name RealTimeProtectionEnabled -Value $DefStatus.RealTimeProtectionEnabled
    
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Antimalware Client Version" -Value $DefStatus.AMProductVersion
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Engine Version" -Value $DefStatus.AMEngineVersion
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Antivirus definition" -Value $DefStatus.AntivirusSignatureVersion
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Antispyware definition" -Value $DefStatus.AntispywareSignatureVersion
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Network inspection system engine version" -Value $DefStatus.NISEngineVersion
	$OutputObj | Add-Member -MemberType NoteProperty -Name "Network inspection system definition version" -Value $DefStatus.NISSignatureVersion
    if ($DefStatus.AntispywareSignatureLastUpdated)
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "AntispywareSignatureLastUpdated" -Value ([Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.AntispywareSignatureLastUpdated))
    }
    else
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "AntispywareSignatureLastUpdated" -Value $null
    }
        if ($DefStatus.AntivirusSignatureLastUpdated)
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "AntivirusSignatureLastUpdated" -Value ([Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.AntivirusSignatureLastUpdated))
    }
    else
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "AntivirusSignatureLastUpdated" -Value $null
    }
        if ($DefStatus.NISSignatureLastUpdated)
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "NISSignatureLastUpdated" -Value ([Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.NISSignatureLastUpdated))
    }
    else
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "NISSignatureLastUpdated" -Value $null
    }
        if ($DefStatus.FullScanStartTime)
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "FullScanStartTime" -Value ([Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.FullScanStartTime))
    }
    else
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "FullScanStartTime" -Value $null
    }
        if ($DefStatus.FullScanEndTime)
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "FullScanEndTime" -Value ([Management.ManagementDateTimeConverter]::ToDateTime($DefStatus.FullScanEndTime))
    }
    else
    {
    $OutputObj | Add-Member -MemberType NoteProperty -Name "FullScanEndTime" -Value $null
    }
    <#$OutputObj | Add-Member -MemberType NoteProperty -Name "AntivirusSignatureLastUpdated" -Value $Sigupd2
    $OutputObj | Add-Member -MemberType NoteProperty -Name "NISSignatureLastUpdated" -Value $Sigupd3

    $OutputObj | Add-Member -MemberType NoteProperty -Name "Full Scan Start time" -Value $scanStart
    $OutputObj | Add-Member -MemberType NoteProperty -Name "Full Scan End time" -Value $scanEnd#>

Write-Output $OutputObj

}

catch{
Write-Error "Either defender is disbaled or there is no such NameSpace available on target computer $($computerName)"
}
}
else{Write-Verbose "$($ComputerName) - Offline, Please check machine is connected to Network."}
}
end{
Write-Verbose "Task Completed - Script ended at $(Get-Date)"
}
}

Function Get-DefenderPreferences
{
Param(
	        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME
)

begin{
}

process{

Write-Verbose "Contacting $($computerName) to fetch defender Preference info.." 

if( Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue){

try{
$DefPreference = Get-WmiObject -Namespace ROOT\Microsoft\Windows\Defender -Class MSFT_MpPreference -ComputerName $computerName -ErrorAction Stop

	$OutputObj = New-Object -TypeName PSobject  
	$OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $DefPreference.PSComputerName
    $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerID -Value $DefPreference.ComputerID
    $OutputObj | Add-Member -MemberType NoteProperty -Name CheckForSignaturesBeforeRunningScan -Value $DefPreference.CheckForSignaturesBeforeRunningScan
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableCatchupFullScan -Value $DefPreference.DisableCatchupFullScan
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableCatchupQuickScan -Value $DefPreference.DisableCatchupQuickScan
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableEmailScanning -Value $DefPreference.DisableEmailScanning
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableScanningMappedNetworkDrivesForFullScan -Value $DefPreference.DisableScanningMappedNetworkDrivesForFullScan
    $OutputObj | Add-Member -MemberType NoteProperty -Name RandomizeScheduleTaskTimes -Value $DefPreference.RandomizeScheduleTaskTimes
    $OutputObj | Add-Member -MemberType NoteProperty -Name ScanOnlyIfIdleEnabled -Value $DefPreference.ScanOnlyIfIdleEnabled

    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableArchiveScanning -Value $DefPreference.DisableArchiveScanning
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableAutoExclusions -Value $DefPreference.DisableAutoExclusions
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableBehaviorMonitoring -Value $DefPreference.DisableBehaviorMonitoring
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableIntrusionPreventionSystem  -Value $DefPreference.DisableIntrusionPreventionSystem 
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableIOAVProtection -Value $DefPreference.DisableIOAVProtection
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisablePrivacyMode -Value $DefPreference.DisablePrivacyMode
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableRealtimeMonitoring -Value $DefPreference.DisableRealtimeMonitoring
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableRemovableDriveScanning -Value $DefPreference.DisableRemovableDriveScanning
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableRestorePoint -Value $DefPreference.DisableRestorePoint
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableScanningNetworkFiles -Value $DefPreference.DisableScanningNetworkFiles
    $OutputObj | Add-Member -MemberType NoteProperty -Name DisableScriptScanning -Value $DefPreference.DisableScriptScanning
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureDisableUpdateOnStartupWithoutEngine -Value $DefPreference.SignatureDisableUpdateOnStartupWithoutEngine
    $OutputObj | Add-Member -MemberType NoteProperty -Name UILockdown  -Value $DefPreference.UILockdown 
    
	$OutputObj | Add-Member -MemberType NoteProperty -Name ExclusionPath -Value $DefPreference.ExclusionPath
	$OutputObj | Add-Member -MemberType NoteProperty -Name ExclusionProcess -Value $DefPreference.ExclusionProcess

	$OutputObj | Add-Member -MemberType NoteProperty -Name ScanScheduleQuickScanTime -Value $DefPreference.ScanScheduleQuickScanTime
    $OutputObj | Add-Member -MemberType NoteProperty -Name RemediationScheduleTime -Value $DefPreference.RemediationScheduleTime
    $OutputObj | Add-Member -MemberType NoteProperty -Name ScanScheduleTime -Value $DefPreference.ScanScheduleTime
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureScheduleTime -Value $DefPreference.SignatureScheduleTime

    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureFallbackOrder -Value $DefPreference.SignatureFallbackOrder
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureScheduleDay -Value $DefPreference.SignatureScheduleDay
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureUpdateCatchupInterval -Value $DefPreference.SignatureUpdateCatchupInterval
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureUpdateInterval  -Value $DefPreference.SignatureUpdateInterval 
    $OutputObj | Add-Member -MemberType NoteProperty -Name SubmitSamplesConsent  -Value $DefPreference.SubmitSamplesConsent
    $OutputObj | Add-Member -MemberType NoteProperty -Name SignatureFirstAuGracePeriod  -Value $DefPreference.SignatureFirstAuGracePeriod

Write-Output $OutputObj

}

catch{
Write-Error "Either defender is disbaled or there is no such NameSpace available on target computer $($computerName)"
}
}
else{Write-Verbose "$($ComputerName) - Offline, Please check machine is connected to Network."}
}
end{
Write-Verbose "Task Completed - Script ended at $(Get-Date)"
}
}

Function Start-DefenderScan
{
Param(
	        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME
)

begin{
}

process{

Write-Verbose "Contacting $($computerName) to fetch defender info" 

if( Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue){

try{

Write-Verbose "Defender scan is running on $($ComputerName)..." 
Write-Verbose "This may take sometime depending upon speed of your computer.."

$DefScan = [WMIClass]"\\$($ComputerName)\ROOT\Microsoft\Windows\Defender:MSFT_MpScan" 

$caption = “Please select the option to scan your $($computerName)”
$message = “Select any one of the option to start scanning”
$choices = [System.Management.Automation.Host.ChoiceDescription[]] `
@(“&Quick”, “&Full”,"&cancel")
[int]$defaultChoice = 0
$choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
 

switch($choiceRTN)
{
 0    { 
 Write-Verbose "Selected Quick Scan.Please wait.."
 $DefScan.start(1)  }
 1    { 
 Write-Verbose "Selected Full Scan.Please wait.."
 $DefScan.start(2)  }
 2    { 
 Write-Verbose "Selected cancel option, script will exit without any scan operation."
 break  }
 
}

}

catch{
Write-Error "Either defender is disbaled or there is no such NameSpace available. Also it might be Generic Faliure on target computer $($computerName)"
}
}
else{Write-Verbose "$($ComputerName) - Offline, Please check machine is connected to Network."}
}
end{
Write-Verbose "Task Completed - Script ended at $(Get-Date)"
}


}

Function Start-SignatureUpdate
{
Param(
	        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME
)
begin{}
process{
Write-Verbose "Contacting $($computerName) to start updating the signature..." 

if( Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue){
try{

$DefUpd= ([WMIClass]"\\$($ComputerName)\ROOT\Microsoft\Windows\Defender:MSFT_MpSignature")

Write-Verbose "This may take sometime depending upon speed of your internet connection.. please wait"

$caption = “Windows Defender Signature update $($computerName)”
$message = “Select any one of the option to start updating the signature”
$choices = [System.Management.Automation.Host.ChoiceDescription[]] `
@(“&Update”, “&Cancel”)
[int]$defaultChoice = 0
$choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
 

switch($choiceRTN)
{
 0    { 
        Write-Verbose "Signature update is inprogress.Please wait.."
        $DefUpd.update(1) 
        $DefUpd.update(2) }
 1    { break }
 
}


}
catch{
Write-Host $_.Exception.Message
Write-Error "Either defender is disbaled or there is no such NameSpace available. Also it might be Generic Faliure on target computer $($computerName)"
}
}
else{Write-Verbose "$($ComputerName) - Offline, Please check machine is connected to Network."}
}
end{
Write-Verbose "Task Completed - Script ended at $(Get-Date)"
}
}

Function Get-MpThreatCatalog
{
Param(
	        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME
)
begin{}
process{
Write-Verbose "Contacting $($computerName) to get the ThreatCatalog ..." 

if( Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue){
try{

$DefTcatalog = Get-WmiObject -Namespace ROOT\Microsoft\Windows\Defender -Class MSFT_MpThreatCatalog -ComputerName $computerName -ErrorAction Stop

$count = $DefTcatalog | Measure-Object | select Count

Write-Host "Total No .of entries available in MpThreatCatalog is -  $($count) "


$caption = “Windows Defender MpThreatCatalog on $($computerName)”
$message = “Select any one of the option:”
$choices = [System.Management.Automation.Host.ChoiceDescription[]] `
@(“&ExporttoExcel”,"&DispalyonCurrentHost", “&Cancel”)
[int]$defaultChoice = 0
$choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
 
Write-Verbose "This may take sometime depending upon no.of Threat Catalog entries are present.. please wait"

switch($choiceRTN)
{
 0    {$DefTcatalog | select PSComputerName,CategoryID,SeverityID,ThreatID,ThreatName,TypeID | Export-Csv -Path $env:SystemDrive\WBG\MpThreatCatalog.csv -NoTypeInformation}
 1    {$DefTcatalog | select PSComputerName,CategoryID,SeverityID,ThreatID,ThreatName,TypeID | Format-Table -AutoSize}
 2    {break}
 
}


}
catch{
Write-Host $_.Exception.Message
Write-Error "Either defender is disbaled or there is no such NameSpace available. Also it might be Generic Faliure on target computer $($computerName)"
}
}
else{Write-Verbose "$($ComputerName) - Offline, Please check machine is connected to Network."}
}
end{
Write-Verbose "Task Completed - Script ended at $(Get-Date)"
}
}