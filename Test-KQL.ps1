<# Test-KQL.ps1 July 2024 Adam Lewis
    Examples of PS related KQL commands to read log analytics
#>

#Connect-AzAccount
Set-AzContext -Subscription "xxxxxxxxxxxxxxxx"
$workspaceName = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
$workspaceRG = "xxxxxxxxxxxxxxxxxxxxxxx"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

$query = "AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == 'Add member to role completed (PIM activation)'
| where Result == 'success'
//| where InitiatedBy.user.id == 'xxxxxxxxxxxxxx-f961-41b0-ade7-6e59c77d6e62'
//| where TargetResources[0].id == 'xxxxxxxxxx-3afb-46b9-b7cf-a126ee74c451'
| sort by TimeGenerated desc
| limit 2"

$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
$kqlQuery.Results.TimeGenerated


$Users = ($kqlQuery.Results.InitiatedBy)
$hash = @{}

ForEach ($UserKQL in $Users){
    $UserArray = (($UserKQL.Split('{')[2]).Split('}').Replace(':','=')[0]).Split(',') 
        #ForEach ($User in $UserArray){
            #$hash[(($User).Split('='))[0]] = (($User).Split('='))[1]
        #}
}