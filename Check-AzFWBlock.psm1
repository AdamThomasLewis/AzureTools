<# Check-AzFWBlock.psm1 July 2024 Adam Lewis
	
	.SYNOPSIS
	Prompts user for IP address and time range.
    Returns firewall blocks in a LAW that contails Azure firewall logs.
	
	.DESCRIPTION
	Prompts user for IP address and time range.
    Returns firewall blocks in a LAW that contails Azure firewall logs.
    Requires a firewall set up with diagnostic settings configured to write to a LAW
  
    Define the following variables:
        $sub = "<YOUR SUBSCRIPTION ID>"
        $workspaceName = "<YOUR LOG ANAYLITCS WORKSPACE NAME>"
        $workspaceRG = "<YOUR RESOURCE GROUP NAME>"

    .EXAMPLE
      # Connect-AzAccount -Subscription "<YOUR SUBSCRIPTION ID>" -Use this if you are not already connected
      Check-AzFWBlock
#>

Function Check-AzFWBlock {

$sub = "<YOUR SUBSCRIPTION ID>"
$workspaceName = "<YOUR LOG ANAYLITCS WORKSPACE NAME>"
$workspaceRG = "<YOUR RESOURCE GROUP NAME>"

Write-Host " ****  Connecting to $WorkspaceName  *****" -ForegroundColor "Green"
Set-AzContext -Subscription $sub |OUT-NULL
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID



Write-Host "`n Using defaults to the following prompts will return all blocks in the last day." -ForegroundColor "Green"

# $SourceIp
Write-Host "`n Enter Source IP or <ENTER> for ANY`n`t" -ForegroundColor "Cyan" -NoNewLine
$SourceIP = Read-Host "Source IP"

# $DestinationIp
Write-Host "`n Enter Destination IP or <ENTER> for ANY`n`t" -ForegroundColor "Magenta" -NoNewLine
$DestinationIP = Read-Host "Destination IP"

# $TimeBegin
Write-Host "`n Enter begin time in 24 hour format (Ex. 7/15/2024 1:00:00)" -ForegroundColor "Cyan" 
Write-Host "`t Press <ENTER> for 1 day ago`t" -ForegroundColor "Green" -NoNewLine
[String]$TimeBegin = Read-Host "Begin Time"
If ($TimeBegin -ne ""){[DateTime]$TimeBegin = $TimeBegin}

# $TimeEnd
Write-Host "`n Enter end time in 24 hour format (Ex. 7/15/2024 1:00:00)" -ForegroundColor "Magenta" 
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

# Invoke Query
$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query

# Output results into an array (Converts from PsCustomObject enumerable)
$Results = $kqlQuery.Results | Select -Property TimeGenerated,Protocol,SourceIp,SourcePort,DestinationIp,DestinationPort

Return $Results
}
