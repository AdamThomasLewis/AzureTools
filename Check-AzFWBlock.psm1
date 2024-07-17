<# Check-AzFWBlock.psm1 July 2024 Adam Lewis
    Prompts user for IP address and looks for blocks in log-cts-ns-p-logs
#>

Function Check-AzFWBlock {
Write-Host " ****   Connecting to"
# Connect-AzAccount -Subscription "2ea0fa31-57dd-464f-b2bd-9b3264fb4f8b"
$sub = "2ea0fa31-57dd-464f-b2bd-9b3264fb4f8b"
$workspaceName = "log-cts-ns-p-logs"
$workspaceRG = "rg-cts-ns-p-1-firewall1"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

Write-Host " ****   Connecting to Subscription $sub   *****" -ForegroundGolor "Green"

Set-AzContext -Subscription $sub |OUT-NULL

Write-Host "`n Using defaults to the following prompts will return all blocks in the last day." -ForegroundColor "Green"

# $SourceIp
Write-Host "`n Enter Source IP or <ENTER> for ANY`n`t" -ForegroundColor "Cyan" -NoNewLine
$SourceIP = Read-Host "Source IP"

# $DestinationIp
Write-Host "`n Enter Destination IP or <ENTER> for ANY`n`t" -ForegroundColor "Magenta" -NoNewLine
$DestinationIP = Read-Host "Destination IP"

# $TimeBegin
Write-Host "`n Enter begin time in 24 hour format (7/15/2024 1:00:00)" -ForegroundColor "Cyan" 
Write-Host "`t Press <ENTER> for 1 day ago`t" -ForegroundColor "Green" -NoNewLine
[String]$TimeBegin = Read-Host "Begin Time"
If ($TimeBegin -ne ""){[DateTime]$TimeBegin = $TimeBegin}

# $TimeEnd
Write-Host "`n Enter end time in 24 hour format (7/15/2024 1:00:00)" -ForegroundColor "Magenta" 
Write-Host "`t Press <ENTER> for NOW`t" -ForegroundColor "Green" -NoNewLine
[String]$TimeEnd = Read-Host "End Time"
If ($TimeEnd -ne ""){[DateTime]$TimeEnd = $TimeEnd}

# Assemble $Query
$query= 'AZFWNetworkRule
| union AZFWApplicationRule, AZFWNatRule, AZFWThreatIntel, AZFWIdpsSignature 
| where Action == "Deny"
'
# Add IP's if necessary
If ($SourceIP -ne ""){
    $query = $query +'| where SourceIp == "' + $SourceIp + '"'
    $query = $query +"`n"
}
If ($DestinationIP -ne ""){
    $query = $query +'| where DestinationIp == "' + $DestinationIp + '"'
    $query = $query +"`n"
}

# Add Begin and end times
If ($TimeBegin -eq ""){$TimeString = '| where TimeGenerated between (ago(1d) .. '}
    ELSE {$TimeString = '| where TimeGenerated between (datetime(' + $TimeBegin.ToString('MM/dd/yyyy')
          $TimeString = $TimeString + ', ' 
          $TimeString = $TimeString+ $TimeBegin.ToString('HH:mm') 
          $TimeString = $TimeString+ ') .. '}

If ($TimeEnd -eq ""){$TimeString = $TimeString + 'now() )'}
ELSE   {$TimeString = $TimeString + 'datetime(' 
        $TimeString = $TimeString + $TimeEnd.ToString('MM/dd/yyyy')
        $TimeString = $TimeString + ', ' 
        $TimeString = $TimeString+ $TimeEnd.ToString('HH:mm') 
        $TimeString = $TimeString+ '))'}

$Query = $Query + $TimeString

$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
$Results = $kqlQuery.Results | Select -Property TimeGenerated,Protocol,SourceIp,SourcePort,DestinationIp,DestinationPort

Return $Results
}