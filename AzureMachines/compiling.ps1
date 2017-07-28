$ProductKey = Read-Host "Please enter your SharePoint 2016 Product Key"
$MachineName = "SPTechCon-SA"
$ConfigData = @{
    AllNodes = @(
        @{
            NodeName = $MachineName
            PSDscAllowPlainTextPassword = $True
        }
    )
}
 
$Parameters = @{
    ParamDomain = "contoso.com"
    ParamInternalDomainControllerIP = "10.0.10.5"; 
    ParamMachineName = $MachineName
    ParamProductKey = $ProductKey
    ParamUsername = "contoso\sp_farm"
    ParamPassword = "pass@word1"
    ParamShareName = "SPTechCon-Share"
}

Login-AzureRmAccount
Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "SPTechCon" -AutomationAccountName "SPTechCon-Automation" -ConfigurationName "SharePoint2016StandAlone" -ConfigurationData $ConfigData -Parameters $Parameters