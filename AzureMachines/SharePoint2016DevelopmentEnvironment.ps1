$DCMachineNameParameter = "lab4dc2"
$SP2016DevMachineNameParameter = "lab4sp3"
$searchIndexDirectory = "c:\SPSearchIndex"
Configuration SharePointDevelopmentEnvironment
{
    param(
        [String]
        $DomainName = "lab4.local",

        [String]
        $DomainControllerIP = "10.1.0.6",

        [String]
        $SPProductKey = "TY6N4-K9WD3-JD2J2-VYKTJ-GVJ2J",

        [String]
        $DCMachineName = $DCMachineNameParameter,

        [String]
        $SP2016DevMachineName = $SP2016DevMachineNameParameter,

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
        $SPTestAccountUserName = "_sptestuser1",

        [String]
        $SPTestAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPTestAccountCredential,

        [String]
        $SPSecondTestAccountUserName = "_sptestuser2",

        [String]
        $SPSecondTestAccountPassword = "123$%^qweRTY",

        [PSCredential]
        $SPSecondTestAccountCredential,

        [String]
        $SPOCSuperUser = "_spocuser",

        [String]
        $SPOCSuperReader = "_spocrdr",

        [String]
        $SPAdminGroupName = "SP Admins",

        [String]
        $SPMemberGroupName = "SP Members",

        [String]
        $SPVisitorGroupName = "SP Visitors",

        [String]
        $SPPassphrase = "123$%^qweRTY",

        [PSCredential]
        $SPPassphraseCredential

    )
    
    $shortDomainName = $DomainName.Substring( 0, $DomainName.IndexOf( "." ) )

    # examining, generatig and requesting credentials
        if ( !$DomainAdminCredential )
        {
            if ( $domainAdminUserName )
            {
                $securedPassword = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
                $domainAdminCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$domainAdminUserName", $securedPassword )
            } else {
                $domainAdminCredential = Get-Credential -Message "Credential with domain administrator privileges";
            }
        }

        if ( !$DomainSafeModeAdministratorPasswordCredential )
        {
            if ( $DomainSafeModeAdministratorPassword )
            {
                $securedPassword = ConvertTo-SecureString $DomainSafeModeAdministratorPassword -AsPlainText -Force
                $DomainSafeModeAdministratorPasswordCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
            } else {
                $DomainSafeModeAdministratorPasswordCredential = Get-Credential -Message "Enter any but not empty login and safe mode password";
            }
        }

        if ( !$SPInstallAccountCredential )
        {
            if ( $SPInstallAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPInstallAccountPassword -AsPlainText -Force
                $SPInstallAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPInstallAccountUserName", $securedPassword )
            } else {
                $SPInstallAccountCredential = Get-Credential -Message "Credential for SharePoint install account";
            }
        }

        if ( !$SPPassphraseCredential )
        {
            if ( $SPPassPhrase )
            {
                $securedPassword = ConvertTo-SecureString $SPPassPhrase -AsPlainText -Force
                $SPPassphraseCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
            } else {
                $SPPassphraseCredential = Get-Credential -Message "Enter any user name and enter pass phrase in password field";
            }
        }

        if ( !$SPFarmAccountCredential )
        {
            if ( $SPFarmAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPFarmAccountPassword -AsPlainText -Force
                $SPFarmAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPFarmAccountUserName", $securedPassword )
            } else {
                $SPFarmAccountCredential = Get-Credential -Message "Credential for SharePoint farm account";
            }
        }

        if ( !$SPWebAppPoolAccountCredential )
        {
            if ( $SPWebAppPoolAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPWebAppPoolAccountPassword -AsPlainText -Force
                $SPWebAppPoolAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPWebAppPoolAccountUserName", $securedPassword )
            } else {
                $SPWebAppPoolAccountCredential = Get-Credential -Message "Credential for SharePoint Web Application app pool account";
            }
        }

        if ( !$SPServicesAccountCredential )
        {
            if ( $SPServicesAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPServicesAccountPassword -AsPlainText -Force
                $SPServicesAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPServicesAccountUserName", $securedPassword )
            } else {
                $SPServicesAccountCredential = Get-Credential -Message "Credential for SharePoint shared services app pool";
            }
        }

        if ( !$SPSearchServiceAccountCredential )
        {
            if ( $SPSearchServiceAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPSearchServiceAccountPassword -AsPlainText -Force
                $SPSearchServiceAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPSearchServiceAccountUserName", $securedPassword )
            } else {
                $SPSearchServiceAccountCredential = Get-Credential -Message "Credential for SharePoint search service account";
            }
        }

        if ( !$SPCrawlerAccountCredential )
        {
            if ( $SPCrawlerAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPCrawlerAccountPassword -AsPlainText -Force
                $SPCrawlerAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPCrawlerAccountUserName", $securedPassword )
            } else {
                $SPCrawlerAccountCredential = Get-Credential -Message "Credential for SharePoint crawler account";
            }
        }

        if ( !$SPTestAccountCredential )
        {
            if ( $SPTestAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPTestAccountPassword -AsPlainText -Force
                $SPTestAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPTestAccountUserName", $securedPassword )
            } else {
                $SPTestAccountCredential = Get-Credential -Message "Credential for SharePoint test user";
            }
        }

        if ( !$SPSecondTestAccountCredential )
        {
            if ( $SPSecondTestAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $SPSecondTestAccountPassword -AsPlainText -Force
                $SPSecondTestAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPSecondTestAccountUserName", $securedPassword )
            } else {
                $SPSecondTestAccountCredential = Get-Credential -Message "Credential for SharePoint test user";
            }
        }

        $SPOCAccountPass = ConvertTo-SecureString "Any3ligiblePa`$`$" -AsPlainText -Force
        $SPOCAccountCredential = New-Object System.Management.Automation.PSCredential( "anyusername", $SPOCAccountPass )

    # credentials are ready

    Import-DscResource -ModuleName xRemoteDesktopAdmin
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DSCResource -Module xSystemSecurity -Name xIEEsc
    Import-DSCResource -ModuleName xDSCDomainJoin
    Import-DSCResource -ModuleName xNetworking
    Import-DSCResource -ModuleName xSQLServer -Name xSQLServerSetup
    Import-DSCResource -ModuleName SharePointDSC

    Node $DCMachineName
    {
        xRemoteDesktopAdmin DCRDPSettings
        {
           Ensure               = 'Present'
           UserAuthentication   = 'NonSecure'
        }

        WindowsFeatureSet DomainFeatures
        {
            Name                    = @("DNS", "AD-Domain-Services", "RSAT-ADDS")
            Ensure                  = 'Present'
            IncludeAllSubFeature    = $true
        } 
                
        xADDomain ADDomain
        {
            DomainName                      = $DomainName
            DomainAdministratorCredential   = $DomainAdminCredential
            SafemodeAdministratorPassword   = $DomainSafeModeAdministratorPasswordCredential
            DependsOn                       = @("[WindowsFeatureSet]DomainFeatures", "[xRemoteDesktopAdmin]DCRDPSettings")
        }

        xWaitForADDomain WaitForDomain
        {
            DomainName              = $DomainName
            DomainUserCredential    = $domainCred
            RetryCount              = $Node.RetryCount
            RetryIntervalSec        = $Node.RetryIntervalSec
            DependsOn               = "[xADDomain]ADDomain"
        }

        xADUser SPInstallAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPInstallAccountCredential.GetNetworkCredential().UserName
            Password    = $SPInstallAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPFarmAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPFarmAccountCredential.GetNetworkCredential().UserName
            Password    = $SPFarmAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPWebAppPoolAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPWebAppPoolAccountCredential.GetNetworkCredential().UserName
            Password    = $SPWebAppPoolAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPServicesAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPServicesAccountCredential.GetNetworkCredential().UserName
            Password    = $SPServicesAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPSearchServiceAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPSearchServiceAccountCredential.GetNetworkCredential().UserName
            Password    = $SPSearchServiceAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPCrawlerAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPCrawlerAccountCredential.GetNetworkCredential().UserName
            Password    = $SPCrawlerAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPOCSuperUserADUser
        {
            DomainName  = $DomainName
            UserName    = $SPOCSuperUser
            Password    = $SPOCAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPOCSuperReaderUser
        {
            DomainName  = $DomainName
            UserName    = $SPOCSuperReader
            Password    = $SPOCAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPTestUser
        {
            DomainName  = $DomainName
            UserName    = $SPTestAccountCredential.GetNetworkCredential().UserName
            Password    = $SPTestAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPSecondTestUser
        {
            DomainName  = $DomainName
            UserName    = $SPSecondTestAccountCredential.GetNetworkCredential().UserName
            Password    = $SPSecondTestAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADGroup SPAdminGroup
        {
            GroupName           = $SPAdminGroupName
            Ensure              = "Present"
            MembersToInclude    = $SPInstallAccountCredential.GetNetworkCredential().UserName
            DependsOn           = "[xADUser]SPInstallAccountUser"
        }

        xADGroup SPMemberGroup
        {
            GroupName           = $SPMemberGroupName
            Ensure              = "Present"
            MembersToInclude    = $SPTestAccountCredential.GetNetworkCredential().UserName
            DependsOn           = "[xADUser]SPInstallAccountUser"
        }

        xADGroup SPVisitorGroup
        {
            GroupName           = $SPVisitorGroupName
            Ensure              = "Present"
            MembersToInclude    = $SPSecondTestAccountCredential.GetNetworkCredential().UserName
            DependsOn           = "[xADUser]SPInstallAccountUser"
        }

    }

    Node $SP2016DevMachineName
    {
        xDNSServerAddress DNSClient
        {
            Address         = $DomainControllerIP
            AddressFamily   = "IPv4"
            InterfaceAlias  = "Ethernet 2"
        }
        Registry LoopBackRegistry
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName   = "DisableLoopbackCheck"
            ValueType   = "DWORD"
            ValueData   = "1"
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
        xDSCDomainJoin DomainJoin
        {
            Domain      = $DomainName
            Credential  = $DomainAdminCredential
            DependsOn   = @("[xDNSServerAddress]DNSClient","[Registry]LoopBackRegistry")
        }
        #Local group
        Group AdminGroup
        {
            GroupName           = "Administrators"
            Credential          = $DomainAdminCredential
            MembersToInclude    = "$shortDomainName\$SPAdminGroupName"
            DependsOn           = "[xDSCDomainJoin]DomainJoin"
        }
        xIEEsc DisableIEEsc
        {
            IsEnabled   = $false
            UserRole    = "Administrators"
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
        xSQLServerSetup SQLSetup
        {
            InstanceName        = "MSSQLServer"
            SourcePath          = "C:\Install\SQL 2016"
            Features            = "SQLENGINE"
            InstallSharedDir    = "C:\Program Files\Microsoft SQL Server"
            SQLSysAdminAccounts = $SPInstallAccountCredential.UserName
            DependsOn           = "[Group]AdminGroup"
        }
        Package SSMS
        {
            Ensure      = "Present"
            Name        = "SMS-Setup-ENU"
            Path        = "C:\Install\SQL SMS 17.1\SSMS-Setup-ENU.exe"
            Arguments   = "/install /passive /norestart"
            ProductId   = "b636c6f4-2183-4b76-b5a0-c8d6422df9f4"
            Credential  = $SPInstallAccountCredential
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
            ProductKey  = $SPProductKey
            DependsOn   = "[SPInstallPrereqs]SP2016Prereqs"
        }
        SPFarm Farm
        {
            Ensure                    = "Present"
            DatabaseServer            = $NodeName
            FarmConfigDatabaseName    = "SP_Config"
            AdminContentDatabaseName  = "SP_AdminContent"
            Passphrase                = $SPPassphraseCredential
            FarmAccount               = $SPFarmAccountCredential
            RunCentralAdmin           = $true
            InstallAccount            = $SPInstallAccountCredential
            CentralAdministrationPort = 7777
            ServerRole                = "SingleServerFarm"
            DependsOn                 = @("[xFireWall]SQLFirewallRule","[SPInstall]InstallSharePoint","[xSQLServerSetup]SQLSetup","[Group]AdminGroup")
        }
        SPManagedAccount ApplicationWebPoolAccount
        {
            AccountName     = $SPWebAppPoolAccountCredential.UserName
            Account         = $SPWebAppPoolAccountCredential
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPFarm]Farm"
        }
        SPWebApplication RootWebApp
        {
            Name                    = "RootWebApp"
            ApplicationPool         = "All Web Application"
            ApplicationPoolAccount  = $SPWebAppPoolAccountCredential.UserName
            Url                     = "http://SP2016_01.bizspark-sap2.local"
            DatabaseName            = "SP_Content_01"
            AuthenticationMethod    = "NTLM"
            InstallAccount          = $SPInstallAccountCredential
            DependsOn               = "[SPManagedAccount]ApplicationWebPoolAccount"
        }
        SPCacheAccounts CacheAccounts
        {
            WebAppUrl            = "http://SP2016_01.bizspark-sap2.local"
            SuperUserAlias       = "$shortDomainName\$SPOCSuperUser"
            SuperReaderAlias     = "$shortDomainName\$SPOCSuperReader"
            InstallAccount       = $SPInstallAccountCredential
            DependsOn            = "[SPWebApplication]RootWebApp"
        }
        SPWebAppPolicy RootWebAppPolicy
        {
            WebAppUrl               = "RootWebApp"
            MembersToInclude        = @(
                MSFT_SPWebPolicyPermissions {
                    Username        = $SPInstallAccountCredential.UserName
                    PermissionLevel = "Full Control"
                    IdentityType    = "Claims"
                }
            )
            SetCacheAccountsPolicy = $true
            InstallAccount         = $SPInstallAccountCredential
            DependsOn              = "[SPCacheAccounts]CacheAccounts"
        }
        SPSite RootPathSite
        {
            Url             = "http://SP2016_01.bizspark-sap2.local"
            OwnerAlias      = $SPInstallAccountCredential.UserName
            Template        = "STS#0"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPWebApplication]RootWebApp"
        }
        SPSite RootHostSite
        {
            Url                         = "http://$NodeName.northeurope.cloudapp.azure.com"
            OwnerAlias                  = $SPInstallAccountCredential.UserName
            Template                    = "STS#0"
            HostHeaderWebApplication    = "http://SP2016_01.bizspark-sap2.local"
            InstallAccount              = $SPInstallAccountCredential
            DependsOn                   = "[SPSite]RootPathSite"
        }

        SPManagedAccount SharePointServicesPoolAccount
        {
            AccountName     = $SPServicesAccountCredential.UserName
            Account         = $SPServicesAccountCredential
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPFarm]Farm"
        }

        SPServiceAppPool SharePointServicesAppPool
        {
            Name            = "SharePoint Services App Pool"
            ServiceAccount  = $SPServicesAccountCredential.UserName
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPManagedAccount]SearchServicePoolAccount"
        }

        SPManagedMetaDataServiceApp ManagedMetadataServiceApp
        {
            DatabaseName    = "SP_Metadata";
            ApplicationPool = "SharePoint Services App Pool";
            ProxyName       = "Managed Metadata Service Application";
            Name            = "Managed Metadata Service Application";
            Ensure          = "Present";
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }
        
        SPSite MySite
        {
            Url                         = "http://$NodeName.northeurope.cloudapp.azure.com/sites/my"
            OwnerAlias                  = $SPInstallAccountCredential.UserName
            Template                    = "SPSMSITEHOST#0"
            HostHeaderWebApplication    = "http://SP2016_01.bizspark-sap2.local"
            InstallAccount              = $SPInstallAccountCredential
            DependsOn                   = "[SPSite]RootPathSite"
        }

        SPUserProfileServiceApp UserProfileServiceApp
        {
            Name                = "User Profile Service Application"
            ApplicationPool     = "SharePoint Services App Pool"
            MySiteHostLocation  = "http://$NodeName.northeurope.cloudapp.azure.com/sites/my"
            ProfileDBName       = "SP_UserProfiles"
            SocialDBName        = "SP_Social"
            SyncDBName          = "SP_ProfileSync"
            EnableNetBIOS       = $false
            FarmAccount         = $SPFarmAccountCredential
            InstallAccount      = $SPInstallAccountCredential
            DependsOn           = @("[SPServiceAppPool]SharePointServicesAppPool","[SPSite]MySite")
        }

        SPSubscriptionSettingsServiceApp SubscriptionSettingsServiceApp
        {
            Name            = "Subscription Settings Service Application"
            ApplicationPool = "SharePoint Services App Pool"
            DatabaseName    = "SP_SubscriptionSettings"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPFarm]Farm"
        }

        SPAppManagementServiceApp AppManagementServiceApp
        {
            Name            = "App Management Service Application"
            ApplicationPool = "SharePoint Services App Pool"
            DatabaseName    = "SP_AppManagement"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPSubscriptionSettingsServiceApp]SubscriptionSettingsServiceApp"
        }

        SPManagedAccount SearchServicePoolAccount
        {
            AccountName     = $SPSearchServiceAccountCredential.UserName
            Account         = $SPSearchServiceAccountCredential
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPFarm]Farm"
        }

        SPServiceAppPool SearchServiceAppPool
        {
            Name            = "SharePoint Search App Pool"
            ServiceAccount  = $SPSearchServiceAccountCredential.UserName
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPManagedAccount]SearchServicePoolAccount"
        }

        SPSite SearchCenterSite
        {
            Url                         = "http://$NodeName.northeurope.cloudapp.azure.com/sites/searchcenter"
            OwnerAlias                  = $SPInstallAccountCredential.UserName
            Template                    = "SRCHCEN#0"
            HostHeaderWebApplication    = "http://SP2016_01.bizspark-sap2.local"
            InstallAccount              = $SPInstallAccountCredential
            DependsOn                   = "[SPSite]RootPathSite"
        }

        SPSearchServiceApp EnterpriseSearchServiceApplication
        {
            Name                        = "Search Service Application";
            Ensure                      = "Present";
            ProxyName                   = "Search Service Application";
            ApplicationPool             = "SharePoint Search App Pool";
            SearchCenterUrl             = "http://$NodeName.northeurope.cloudapp.azure.com/sites/searchcenter/pages";
            DatabaseName                = "SP_Search";
            DefaultContentAccessAccount = $SPCrawlerAccountCredential;
            InstallAccount              = $SPInstallAccountCredential
            DependsOn                   = @("[SPServiceAppPool]SearchServiceAppPool","[SPSite]SearchCenterSite")
        }

        File "IndexFolder"
        {
            DestinationPath = $searchIndexDirectory
            Type            = "Directory"
        }

        SPSearchTopology SearchTopology
        {
            ServiceAppName          = "Search Service Application";
            ContentProcessing       = @($NodeName);
            AnalyticsProcessing     = @($NodeName);
            IndexPartition          = @($NodeName);
            Crawler                 = @($NodeName);
            Admin                   = @($NodeName);
            QueryProcessing         = @($NodeName);
            FirstPartitionDirectory = $searchIndexDirectory;
            InstallAccount          = $SPInstallAccountCredential
            DependsOn = @("[SPSearchServiceApp]EnterpriseSearchServiceApplication","[File]IndexFolder");
        }

        SPSearchContentSource WebsiteSource
        {
            ServiceAppName       = "Search Service Application"
            Name                 = "Local SharePoint sites"
            ContentSourceType    = "SharePoint"
            Addresses            = @("http://SP2016_01.bizspark-sap2.local")
            CrawlSetting         = "CrawlEverything"
            ContinuousCrawl      = $true
            FullSchedule         = MSFT_SPSearchCrawlSchedule{
                                    ScheduleType = "Weekly"
                                    CrawlScheduleDaysOfWeek = @("Monday", "Wednesday", "Friday")
                                    StartHour = "3"
                                    StartMinute = "0"
                                   }
            Priority             = "Normal"
            Ensure               = "Present"
            InstallAccount       = $SPInstallAccountCredential
            DependsOn            = "[SPSearchTopology]SearchTopology"
        }
    }
}

$configurationData = @{ AllNodes = @(
    @{ NodeName = $DCMachineNameParameter; PSDscAllowPlainTextPassword = $True },
    @{ NodeName = $SP2016DevMachineNameParameter; PSDscAllowPlainTextPassword = $True }
) }
SharePointDevelopmentEnvironment -ConfigurationData $configurationData

