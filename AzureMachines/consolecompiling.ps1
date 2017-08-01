$domainName = "lab2.local"
$SPProductKey = "TY6N4-K9WD3-JD2J2-VYKTJ-GVJ2J"
$domainAdminUserName = "dauser1"
$domainAdminPassword = "123$%^qweRTY"
$domainSafemodeAdministratorPassword = "123$%^qweRTY"
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

Configuration SharePointDevelopmentEnvironment
{
    param(
        [String]
        $DomainName = "lab3.local",

        [String]
        $DomainAdminUserName = "dauser1",

        [String]
        $DomainAdminPassword = "123$%^qweRTY",

        [PSCredential]
        $DomainAdminCredential,

        [String]
        $DomainSafeModeAdministratorPassword = "123$%^qweRTY",

        [PSCredential]
        $DomainSafeModeAdministratorPasswordCredential,

        [String]
        $SPInstallAccountUserName = "_spadm",

        [String]
        $SPInstallAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPInstallAccountCredential,

        [String]
        $SPProductKey = "TY6N4-K9WD3-JD2J2-VYKTJ-GVJ2J",

        [String]
        $SPPassphrase = "123$%^qweRTY",

        [PSCredential]
        $SPPassphraseCredential,

        [String]
        $SPFarmAccountUserName = "_spfrm",

        [String]
        $SPFarmAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPFarmAccountCredential,

        [String]
        $SPWebAppPoolAccountUserName = "_spwebapppool",

        [String]
        $SPWebAppPoolAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPWebAppPoolAccountCredential,

        [String]
        $SPServicesAccountUserName = "_spsrv",

        [String]
        $SPServicesAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPServicesAccountCredential,

        [String]
        $SPSearchServiceAccountUserName = "_spsrchsrv",

        [String]
        $SPSearchServiceAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPSearchServiceAccountCredential,

        [String]
        $SPCrawlerAccountUserName = "_spcrawler",

        [String]
        $SPCrawlerAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPCrawlerAccountCredential,

        [String]
        $SPOCSuperUser = "_spocuser",

        [String]
        $SPOCSuperReader = "_spocrdr",

        [String]
        $SPAdminGroupName,

        [String]
        $SPMemberGroupName,

        [String]
        $SPVisitorGroupName
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DSCResource -Module xSystemSecurity -Name xIEEsc
    Import-DSCResource -ModuleName xDSCDomainJoin
    Import-DSCResource -ModuleName xNetworking
    Import-DSCResource -ModuleName xSQLServer
    Import-DSCResource -ModuleName SharePointDSC

    # examining, generatig and requesting credentials
        if ( !$DomainAdminCredential )
        {
            if ( $domainAdminUserName )
            {
                $securedPassword = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
                $domainAdminCredential = New-Object System.Management.Automation.PSCredential( $domainAdminUserName, $securedPassword )
            } else {
                $domainAdminCredential = Get-Credential -Message "Credential for joining the server to domain";
            }
        }

        if ( !$DomainSafeModeAdministratorPassword )
        {
            $DomainSafeModeAdministratorPassword = $DomainSafeModeAdministratorPasswordCredential.Password
        }

        if ( !$SPInstallAccountCredential )
        {
            if ( $SPInstallAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPInstallAccountPassword -AsPlainText -Force
                $SPInstallAccountCredential = New-Object System.Management.Automation.PSCredential( $SPInstallAccountUserName, $securedPassword )
            } else {
                $SPInstallAccountCredential = Get-Credential -Message "Credential for SharePoint install account";
            }
        }

        if ( !$SPPassphraseCredential )
        {
            if ( $SPPassPhrase )
            {
                $securedPassword = ConvertTo-SecureString $SPPassPhrase -AsPlainText -Force
                $passphraseCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
            } else {
                $passphraseCredential = Get-Credential -Message "Enter any user name and enter pass phrase in password field";
            }
        }

        if ( !$SPFarmAccountCredential )
        {
            if ( $SPFarmAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPFarmAccountPassword -AsPlainText -Force
                $SPFarmAccountCredential = New-Object System.Management.Automation.PSCredential( $SPFarmAccountUserName, $securedPassword )
            } else {
                $SPFarmAccountCredential = Get-Credential -Message "Credential for SharePoint farm account";
            }
        }

        if ( !$SPWebAppPoolAccountCredential )
        {
            if ( $SPWebAppPoolAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPWebAppPoolAccountPassword -AsPlainText -Force
                $SPWebAppPoolAccountCredential = New-Object System.Management.Automation.PSCredential( $SPWebAppPoolAccountUserName, $securedPassword )
            } else {
                $SPWebAppPoolAccountCredential = Get-Credential -Message "Credential for SharePoint Web Application app pool account";
            }
        }

        if ( !$SPServicesAccountCredential )
        {
            if ( $SPServicesAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPServicesAccountPassword -AsPlainText -Force
                $SPServicesAccountCredential = New-Object System.Management.Automation.PSCredential( $SPServicesAccountUserName, $securedPassword )
            } else {
                $SPServicesAccountCredential = Get-Credential -Message "Credential for SharePoint shared services app pool";
            }
        }

        if ( !$SPSearchServiceAccountCredential )
        {
            if ( $SPSearchServiceAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPSearchServiceAccountPassword -AsPlainText -Force
                $SPSearchServiceAccountCredential = New-Object System.Management.Automation.PSCredential( $SPSearchServiceAccountUserName, $securedPassword )
            } else {
                $SPSearchServiceAccountCredential = Get-Credential -Message "Credential for SharePoint search service account";
            }
        }

        if ( !$SPCrawlerAccountCredential )
        {
            if ( $SPCrawlerAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPCrawlerAccountPassword -AsPlainText -Force
                $SPCrawlerAccountCredential = New-Object System.Management.Automation.PSCredential( $SPCrawlerAccountUserName, $securedPassword )
            } else {
                $SPCrawlerAccountCredential = Get-Credential -Message "Credential for SharePoint crawler account";
            }
        }
    # credentials are ready

    $DCNodes = ( $AllNodes | ? { $_.Role -contains "DC" } ).NodeName;
    $SPDevNodes = ( $AllNodes | ? { $_.Role -contains "Search" } ).NodeName;

    Node $DCNodes
    {        
        WindowsFeature ADDSFeature
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }
        
        WindowsFeature ADDSToolsFeature
        {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }
        
        xADDomain FirstDS
        {
            DomainName                      = $DomainName
            DomainAdministratorCredential   = $domainAdminAccount
            SafemodeAdministratorPassword   = $DomainSafeModeAdministratorPasswordCredential
            DependsOn                       = "[WindowsFeature]ADDSFeature"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName              = $DomainName
            DomainUserCredential    = $domainCred
            RetryCount              = $Node.RetryCount
            RetryIntervalSec        = $Node.RetryIntervalSec
            DependsOn               = "[xADDomain]FirstDS"
        }

        xADUser SPInstallAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPInstallAccount.UserName
            Password    = $SPInstallAccount.Password
            DependsOn   = "[xWaitForADDomain]DscForestWait"
        }
        xADGroup ExampleGroup
        {
            GroupName           = "SPAdmins"
            Ensure              = 'Present'
            MembersToInclude    = { $SPInstallAccount.UserName }
            DependsOn           = "[xADUser]SPInstallAccountUser"
        }
    }
    Node $SPDevNodes
    {
        LocalConfigurationManager
        {
            CertificateId       = "1A4C832263684569705D6DBF8983B5F4DAA4BBF1"
            RebootNodeIfNeeded  = $true
        }
        xIEEsc DisableIEEsc
        {
            IsEnabled   = $false
            UserRole    = "Administrators"
        }
        xFireWall SQLFirewallRule
        {
            Name        = "AllowSQLConnection"
            DisplayName = "Allow SQL Connection"
            Group       = "DSC Rules"
            Ensure      = "Present"
            Enabled     = "True"
            Profile     = ("Domain")
            Direction   = "InBound"
            LocalPort   = ("1433")
            Protocol    = "TCP"
            Description = "Firewall rule to allow SQL communication"
        }
        xDSCDomainJoin Join
        {
            Domain      = $DomainName
            Credential  = $domainAdminAccount
        }
        #Local group
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
            Ensure      = "Present"
            BinaryDir   = "C:\Install\SharePoint 2016"
            ProductKey  = $productKey
            DependsOn   = "[SPInstallPrereqs]SP2016Prereqs"
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

$configurationData = @{
    AllNodes = @(
        @{
            NodeName = "lab3dc1"
            PSDscAllowPlainTextPassword = $True
            Role = @("DC")
        },
        @{
            NodeName = "lab3sp1"
            PSDscAllowPlainTextPassword = $True
            Role = @("SPDev")
        }
    )
}


SharePointDevelopmentEnvironment -ConfigurationData $configurationData
