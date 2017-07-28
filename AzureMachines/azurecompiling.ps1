$domainName = "lab2.local"

$SPProductKey = "TY6N4-K9WD3-JD2J2-VYKTJ-GVJ2J"

$domainAdminUserName = "dauser1"
$domainAdminPassword = "123$%^qweRTY"
    
$SPInstallAccountUserName = "_spadm"
$SPInstallAccountPassword = "123$%^qweRTY"

$SPPassPhrase = "123$%^qweRTY"

$SPFarmAccountUserName = "_spfrm"
$SPFarmAccountPassword = "123$%^qweRTY"
    
$SPServicesAccountUserName = "_spsrv"
$SPServicesAccountPassword = "123$%^qweRTY"
    
$SPWebAppPoolAccountName = "_spwebapppool"
$SPWebAppPoolAccountPassword = "123$%^qweRTY"
    
$SPSearchServiceAccountUserName = "_spsrchsrv"
$SPSearchServiceAccountPassword = "123$%^qweRTY"

$SPCrawlerAccountUserName = "_spcrawler"
$SPCrawlerAccountPassword = "123$%^qweRTY"

$SPAdminGroupName = "SP Admins"
$SPMemberGroupName = "SP Members"
$SPVisitorGroupName = "SP Visitors"

# examining, generatig and requesting credentials
    if ( $domainAdminUserName )
    {
        $securedPassword = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
        $domainAdminCredential = New-Object System.Management.Automation.PSCredential( $domainAdminUserName, $securedPassword )
    } else {
        $domainAdminCredential = Get-Credential -Message "Credential for joining the server to domain";
    }

    if ( $SPInstallAccountUserName )
    {
        $securedPassword = ConvertTo-SecureString $SPInstallAccountPassword -AsPlainText -Force
        $SPInstallAccountCredential = New-Object System.Management.Automation.PSCredential( $SPInstallAccountUserName, $securedPassword )
    } else {
        $SPInstallAccountCredential = Get-Credential -Message "Credential for SharePoint install account";
    }

    if ( !$SPProductKey )
    {
        $SPProductKey = Read-Host "Please enter your SharePoint 2016 Product Key"
    }

    if ( $SPPassPhrase )
    {
        $securedPassword = ConvertTo-SecureString $SPPassPhrase -AsPlainText -Force
        $passphraseCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
    } else {
        $passphraseCredential = Get-Credential -Message "Enter any user name and enter pass phrase in password field";
    }

    if ( $SPFarmAccountUserName )
    {
        $securedPassword = ConvertTo-SecureString $SPFarmAccountPassword -AsPlainText -Force
        $SPFarmAccountCredential = New-Object System.Management.Automation.PSCredential( $SPFarmAccountUserName, $securedPassword )
    } else {
        $SPFarmAccountCredential = Get-Credential -Message "Credential for SharePoint farm account";
    }

    if ( $SPWebAppPoolAccountName )
    {
        $securedPassword = ConvertTo-SecureString $SPWebAppPoolAccountPassword -AsPlainText -Force
        $SPWebAppPoolAccountCredential = New-Object System.Management.Automation.PSCredential( $SPWebAppPoolAccountName, $securedPassword )
    } else {
        $SPWebAppPoolAccountCredential = Get-Credential -Message "Credential for SharePoint Web Application app pool account";
    }

    if ( $SPServicesAccountUserName )
    {
        $securedPassword = ConvertTo-SecureString $SPServicesAccountPassword -AsPlainText -Force
        $SPServicesAccountCredential = New-Object System.Management.Automation.PSCredential( $SPServicesAccountUserName, $securedPassword )
    } else {
        $SPServicesAccountCredential = Get-Credential -Message "Credential for SharePoint shared services app pool";
    }

    if ( $SPSearchServiceAccountUserName )
    {
        $securedPassword = ConvertTo-SecureString $SPSearchServiceAccountPassword -AsPlainText -Force
        $SPSearchServiceAccountCredential = New-Object System.Management.Automation.PSCredential( $SPSearchServiceAccountUserName, $securedPassword )
    } else {
        $SPSearchServiceAccountCredential = Get-Credential -Message "Credential for SharePoint search service account";
    }

    if ( $SPCrawlerAccountUserName )
    {
        $securedPassword = ConvertTo-SecureString $SPCrawlerAccountPassword -AsPlainText -Force
        $SPCrawlerAccountCredential = New-Object System.Management.Automation.PSCredential( $SPCrawlerAccountUserName, $securedPassword )
    } else {
        $SPCrawlerAccountCredential = Get-Credential -Message "Credential for SharePoint crawler account";
    }
# credentials are ready

$parameters = @{
    DomainName = $domainName
    DomainAdminAccount = $domainAdminCredential
    SPInstallAccount = $SPInstallAccountCredential
    SPProductKey = $SPProductKey
    SPPassphrase = $SPPassphraseCredential
    SPFarmAccount = $SPFarmAccountCredential
    SPWebAppPoolAccount = $SPWebAppPoolAccountCredential
    SPServicesAccount = $SPServicesAccountCredential
    SPSearchServiceAccount = $SPSearchServiceAccountCredential
    SPCrawlerAccount = $SPCrawlerAccountCredential
    
    SPAdminGroupName = $SPAdminGroupName
    SPMemberGroupName = $SPMemberGroupName
    SPVisitorGroupName = $SPVisitorGroupName
}

SharePointDevelopmentEnvironment -Parameters $parameters -ConfigurationData configurationdata.psd1
#Login-AzureRmAccount
#Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "development" -AutomationAccountName "lab2-automation" -ConfigurationName "SharePointDevelopmentEnvironment" -ConfigurationData configurationdata.psd1 -Parameters $parameters