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
        $SPPassphraseCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
    } else {
        $SPPassphraseCredential = Get-Credential -Message "Enter any user name and enter pass phrase in password field";
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

# main configuration zone
Configuration SharePointDevelopmentEnvironment
{
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $DomainName = "bizspark-sap2.local",

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $DomainAdminAccount,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPInstallAccount,

        [Parameter(Mandatory = $true)]
        [String]
        $SPProductKey,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPPassphrase,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPFarmAccount,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPWebAppPoolAccount,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPServicesAccount,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPSearchServiceAccount,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $SPCrawlerAccount,

        [Parameter(Mandatory = $true)]
        [String]
        $SPAdminGroupName,

        [Parameter(Mandatory = $true)]
        [String]
        $SPMemberGroupName,

        [Parameter(Mandatory = $true)]
        [String]
        $SPVisitorGroupName
    )
    Import-DSCResource -Module xSystemSecurity -Name xIEEsc
    Import-DSCResource -ModuleName xDSCDomainJoin
    Import-DSCResource -ModuleName xNetworking
    Import-DSCResource -ModuleName SharePointDSC
    Import-DSCResource -ModuleName xSQLServer

    $DCNodes = ( $AllNodes | ? { $_.Role -contains "DC" } ).NodeName;
    $SPDevNodes = ( $AllNodes | ? { $_.Role -contains "SPDev" } ).NodeName;

    Node $SPDevNodes
    {
        LocalConfigurationManager
        {
            CertificateId       = "1A4C832263684569705D6DBF8983B5F4DAA4BBF1"
            RebootNodeIfNeeded  = $true
        }
        xIEEsc DisableIEEsc
        {
            IsEnabled = $false
            UserRole = "Administrators"
        }
        xFireWall SQLFirewallRule
        {
            Name = "AllowSQLConnection"
            DisplayName = "Allow SQL Connection"
            Group = "DSC Rules"
            Ensure = "Present"
            Enabled = "True"
            Profile = ("Domain")
            Direction = "InBound"
            LocalPort = ("1433")
            Protocol = "TCP"
            Description = "Firewall rule to allow SQL communication"
        }
        xDSCDomainJoin Join
        {
            Domain      = $DomainName
            Credential  = $domainAdminAccount
        }
        Group AdminGroup
        {
            GroupName           = "Administrators"
            Credential          = $domainAdminAccount
            MembersToInclude    = $setupAccount.UserName
            DependsOn           = "[xDSCDomainJoin]Join"
        }
        xHostsFile WAHostEntry
        {
            HostName  = "SP2016_01.bizspark-sap2.local"
            IPAddress = "127.0.0.1"
            Ensure    = "Present"
        }
        xHostsFile SiteHostEntry
        {
            HostName  = "$NodeName.northeurope.cloudapp.azure.com"
            IPAddress = "127.0.0.1"
            Ensure    = "Present"
        }
        Registry LoopBackRegistry
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName   = "DisableLoopbackCheck"
            ValueType   = "DWORD"
            ValueData   = "1"
        }
        xSQLServerSetup SQLSetup
        {
            InstanceName        = "MSSQLServer"
            SourcePath          = "C:\Install\SQL 2016"
            Features            = "SQLENGINE"
            InstallSharedDir    = "C:\Program Files\Microsoft SQL Server"
            SQLSysAdminAccounts = $setupAccount.UserName
            DependsOn           = "[Group]AdminGroup"
        }
        Package SSMS
        {
            Ensure      = "Present"
            Name        = "SMS-Setup-ENU"
            Path        = "C:\Install\SQL SMS 17.1\SSMS-Setup-ENU.exe"
            Arguments   = "/install /passive /norestart"
            ProductId   = "b636c6f4-2183-4b76-b5a0-c8d6422df9f4"
            Credential  = $setupAccount
            DependsOn   = "[Group]AdminGroup"
        }
        SPInstallPrereqs SP2016Prereqs
        {
            InstallerPath   = "C:\Install\SharePoint 2016\Prerequisiteinstaller.exe"
            OnlineMode      = $true
            DependsOn       = "[Registry]LoopBackRegistry"
        }
        SPInstall InstallSharePoint 
        { 
            Ensure = "Present"
            BinaryDir = "C:\Install\SharePoint 2016"
            ProductKey = $productKey
            DependsOn = "[SPInstallPrereqs]SP2016Prereqs"
        }
        SPCreateFarm CreateFarm
        {
            DatabaseServer            = $NodeName
            FarmConfigDatabaseName    = "SP_Config"
            AdminContentDatabaseName  = "SP_AdminContent"
            Passphrase                = $Passphrase
            FarmAccount               = $FarmAccount
            InstallAccount            = $SetupAccount
            ServerRole                = "SingleServerFarm"
            CentralAdministrationPort = 7777
            DependsOn                 = @("[xFireWall]SQLFirewallRule","[SPInstall]InstallSharePoint","[xSQLServerSetup]SQLSetup")
        }
        SPManagedAccount ApplicationWebPoolAccount
        {
            AccountName     = $appPoolAccount.UserName
            Account         = $appPoolAccount
            InstallAccount  = $SetupAccount
            DependsOn       = "[SPCreateFarm]CreateFarm"
        }
        SPServiceAppPool WebAppPool
        {
            Name            = "All Web Applications"
            ServiceAccount  = $appPoolAccount.UserName
            InstallAccount  = $SetupAccount
            DependsOn       = "[SPManagedAccount]ApplicationWebPoolAccount"
        }
        SPWebApplication RootWebApp
        {
            Name                    = "RootWebApp"
            ApplicationPool         = "All Web Application"
            ApplicationPoolAccount  = $appPoolAccount.UserName
            Url                     = "http://SP2016_01.bizspark-sap2.local"
            DatabaseName            = "SP_Content_01"
            AuthenticationMethod    = "NTLM"
            InstallAccount          = $SetupAccount
            DependsOn               = "[SPManagedAccount]ApplicationWebPoolAccount"
        }
        SPCacheAccounts CacheAccounts
        {
            WebAppUrl            = "http://SP2016_01.bizspark-sap2.local"
            SuperUserAlias       = "bizspark-sap2\_spcsuser"
            SuperReaderAlias     = "bizspark-sap2\_spcsreader"
            InstallAccount       = $SetupAccount
            DependsOn            = "[SPWebApplication]RootWebApp"
        }
        SPWebAppPolicy RootWebAppPolicy
        {
            WebAppUrl               = "RootWebApp"
            MembersToInclude        = @(
                MSFT_SPWebPolicyPermissions {
                    Username        = $SetupAccount.UserName
                    PermissionLevel = "Full Control"
                    IdentityType    = "Claims"
                }
            )
            SetCacheAccountsPolicy = $true
            InstallAccount         = $SetupAccount
            DependsOn              = "[SPCacheAccounts]CacheAccounts"
        }
        SPSite RootPathSite
        {
            Url             = "http://SP2016_01.bizspark-sap2.local"
            OwnerAlias      = $SetupAccount.UserName
            Template        = "STS#0"
            InstallAccount  = $SetupAccount
            DependsOn       = "[SPWebApplication]RootWebApp"
        }
        SPSite RootHostSite
        {
            Url                         = "http://$NodeName.northeurope.cloudapp.azure.com"
            OwnerAlias                  = $SetupAccount.UserName
            Template                    = "STS#0"
            HostHeaderWebApplication    = "http://SP2016_01.bizspark-sap2.local"
            InstallAccount              = $SetupAccount
            DependsOn                   = "[SPSite]RootPathSite"
        }
    }
}

SharePointDevelopmentEnvironment -DomainName $domainName -DomainAdmin $domainAdminCredential -SPInstallAccount $SPInstallAccountCredential -SPProductKey $SPProductKey -SPPassphrase $SPPassphraseCredential -SPFarmAccount $SPFarmAccountCredential -SPWebAppPoolAccount $SPWebAppPoolAccountCredential -SPServicesAccount $SPServicesAccountCredential -SPSearchServiceAccount $SPSearchServiceAccountCredential -SPCrawlerAccount $SPCrawlerAccountCredential -SPAdminGroupName $SPAdminGroupName -SPMemberGroupName $SPMemberGroupName -SPVisitorGroupName $SPVisitorGroupName -ConfigurationData configurationdata.psd1
#Login-AzureRmAccount
#Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "development" -AutomationAccountName "lab2-automation" -ConfigurationName "SharePointDevelopmentEnvironment" -ConfigurationData configurationdata.psd1 -Parameters $parameters