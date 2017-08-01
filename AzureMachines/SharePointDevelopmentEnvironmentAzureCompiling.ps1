$configurationData = @{
    AllNodes = @(
        @{
            NodeName = "lab3dc3"
            PSDscAllowPlainTextPassword = $True
        }
    )
}

Login-AzureRmAccount
Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "development" -AutomationAccountName "lab3automation" -ConfigurationName "SharePointDevelopmentEnvironment" -ConfigurationData $configurationData