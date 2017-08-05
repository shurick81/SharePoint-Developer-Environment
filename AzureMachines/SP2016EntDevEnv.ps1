Configuration SP2016EntDevEnv
{
    param(
        $configParameters
    )
    $DomainName = $configParameters.DomainName;
    $domainAdminUserName = $configParameters.DomainAdminUserName;
    $SPInstallAccountUserName = $configParameters.SPInstallAccountUserName;
    $SPFarmAccountUserName = $configParameters.SPFarmAccountUserName;
    $SPWebAppPoolAccountUserName = $configParameters.SPWebAppPoolAccountUserName;
    $SPServicesAccountUserName = $configParameters.SPServicesAccountUserName;
    $SPSearchServiceAccountUserName = $configParameters.SPSearchServiceAccountUserName;
    $SPCrawlerAccountUserName = $configParameters.SPCrawlerAccountUserName;
    $SPPassPhrase = $configParameters.SPPassPhrase;
    $searchIndexDirectory = $configParameters.searchIndexDirectory;

    $shortDomainName = $DomainName.Substring( 0, $DomainName.IndexOf( "." ) )
    $siteCollectionHostName = "sp2016entdev.$DomainName"

    # examining, generatig and requesting credentials
        if ( !$DomainAdminCredential )
        {
            if ( $domainAdminUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.DomainAdminPassword -AsPlainText -Force
                $domainAdminCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$domainAdminUserName", $securedPassword )
            } else {
                $domainAdminCredential = Get-Credential -Message "Credential with domain administrator privileges";
            }
        }

        if ( !$SPInstallAccountCredential )
        {
            if ( $SPInstallAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPInstallAccountPassword -AsPlainText -Force
                $SPInstallAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPInstallAccountUserName", $securedPassword )
            } else {
                $SPInstallAccountCredential = Get-Credential -Message "Credential for SharePoint install account";
            }
        }

        if ( !$SPPassphraseCredential )
        {
            if ( $SPPassPhrase )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPPassPhrase -AsPlainText -Force
                $SPPassphraseCredential = New-Object System.Management.Automation.PSCredential( "anyidentity", $securedPassword )
            } else {
                $SPPassphraseCredential = Get-Credential -Message "Enter any user name and enter pass phrase in password field";
            }
        }

        if ( !$SPFarmAccountCredential )
        {
            if ( $SPFarmAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPFarmAccountPassword -AsPlainText -Force
                $SPFarmAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPFarmAccountUserName", $securedPassword )
            } else {
                $SPFarmAccountCredential = Get-Credential -Message "Credential for SharePoint farm account";
            }
        }

        if ( !$SPWebAppPoolAccountCredential )
        {
            if ( $SPWebAppPoolAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPWebAppPoolAccountPassword -AsPlainText -Force
                $SPWebAppPoolAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPWebAppPoolAccountUserName", $securedPassword )
            } else {
                $SPWebAppPoolAccountCredential = Get-Credential -Message "Credential for SharePoint Web Application app pool account";
            }
        }

        if ( !$SPServicesAccountCredential )
        {
            if ( $SPServicesAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPServicesAccountPassword -AsPlainText -Force
                $SPServicesAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPServicesAccountUserName", $securedPassword )
            } else {
                $SPServicesAccountCredential = Get-Credential -Message "Credential for SharePoint shared services app pool";
            }
        }

        if ( !$SPSearchServiceAccountCredential )
        {
            if ( $SPSearchServiceAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPSearchServiceAccountPassword -AsPlainText -Force
                $SPSearchServiceAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPSearchServiceAccountUserName", $securedPassword )
            } else {
                $SPSearchServiceAccountCredential = Get-Credential -Message "Credential for SharePoint search service account";
            }
        }

        if ( !$SPCrawlerAccountCredential )
        {
            if ( $SPCrawlerAccountUserName )
            {
                $securedPassword = ConvertTo-SecureString $configParameters.SPCrawlerAccountPassword -AsPlainText -Force
                $SPCrawlerAccountCredential = New-Object System.Management.Automation.PSCredential( "$shortDomainName\$SPCrawlerAccountUserName", $securedPassword )
            } else {
                $SPCrawlerAccountCredential = Get-Credential -Message "Credential for SharePoint crawler account";
            }
        }

    # credentials are ready

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -Module xSystemSecurity -Name xIEEsc
    Import-DSCResource -ModuleName xDSCDomainJoin
    Import-DSCResource -ModuleName xNetworking
    Import-DSCResource -ModuleName xSQLServer -Name xSQLServerSetup
    Import-DSCResource -ModuleName SharePointDSC
    Import-DscResource -ModuleName xWebAdministration

    Node $SP2016EntDevMachineName
    {
        xDNSServerAddress DNSClient
        {
            Address         = $configParameters.DomainControllerIP
            AddressFamily   = "IPv4"
            InterfaceAlias  = "Ethernet 3"
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
            MembersToInclude    = "$shortDomainName\$($configParameters.SPAdminGroupName)"
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
            HostName  = $siteCollectionHostName
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
            ProductKey  = $configParameters.SPProductKey
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
            CentralAdministrationPort = 7777
            ServerRole                = "SingleServerFarm"
            InstallAccount            = $SPInstallAccountCredential
            DependsOn                 = @("[xFireWall]SQLFirewallRule","[SPInstall]InstallSharePoint","[xSQLServerSetup]SQLSetup","[Group]AdminGroup")
        }

        SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
        {
            LogPath         = "C:\Logs\ULS"
            LogSpaceInGB    = 10
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPFarm]Farm"
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

        xIISLogging RootWebAppIISLogging
        {
            LogPath = "C:\Logs\IIS"
        }

        SPCacheAccounts CacheAccounts
        {
            WebAppUrl            = "http://SP2016_01.bizspark-sap2.local"
            SuperUserAlias       = "$shortDomainName\$($configParameters.SPOCSuperUser)"
            SuperReaderAlias     = "$shortDomainName\$($configParameters.SPOCSuperReader)"
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
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPWebApplication]RootWebApp"
        }

        SPSite RootHostSite
        {
            Url                         = "http://$siteCollectionHostName"
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

        SPAccessServiceApp AccessServices
        {
            Name            = "Access Services"
            ApplicationPool = "SharePoint Services App Pool";
            DatabaseServer  = $NodeName
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPBCSServiceApp BCSServiceApp
        {
            Name            = "Business Data Connectivity Service"
            ApplicationPool = "SharePoint Services App Pool";
            DatabaseName    = "SP_BCS"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPExcelServiceApp ExcelServices
        {
            Name                    = "Excel Services Service Application"
            ApplicationPool         = "SharePoint Services App Pool";
            InstallAccount          = $SPInstallAccountCredential;
            DependsOn               = "[SPServiceAppPool]SharePointServicesAppPool";
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

        SPPerformancePointServiceApp PerformancePoint
        {
            Name            = "PerformancePoint Service Application"
            ApplicationPool = "SharePoint Services App Pool";
            DatabaseName    = "SP_PerformancePoint"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
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
            Url                         = "http://$siteCollectionHostName/sites/searchcenter"
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
            ApplicationPool             = "SharePoint Search App Pool";
            SearchCenterUrl             = "http://$siteCollectionHostName/sites/searchcenter/pages";
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

        SPSecureStoreServiceApp SecureStoreServiceApp
        {
            Name            = "Secure Store Service"
            ApplicationPool = "SharePoint Services App Pool"
            AuditingEnabled = $true
            DatabaseName    = "SP_SecureStoreService"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPStateServiceApp StateServiceApp
        {
            Name            = "State Service"
            DatabaseName    = "SP_StateService"
            Ensure          = "Present"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPSubscriptionSettingsServiceApp SubscriptionSettingsServiceApp
        {
            Name            = "Subscription Settings Service Application"
            ApplicationPool = "SharePoint Services App Pool"
            DatabaseName    = "SP_SubscriptionSettings"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPAppManagementServiceApp AppManagementServiceApp
        {
            Name            = "App Management Service Application"
            ApplicationPool = "SharePoint Services App Pool"
            DatabaseName    = "SP_AppManagement"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPSubscriptionSettingsServiceApp]SubscriptionSettingsServiceApp"
        }

        SPUsageApplication UsageApplication 
        {
            Name                    = "Usage Service Application"
            DatabaseName            = "SP_Usage"
            UsageLogCutTime         = 5
            UsageLogLocation        = "C:\Logs\Usage"
            UsageLogMaxFileSizeKB   = 1024
            InstallAccount          = $SPInstallAccountCredential
            DependsOn               = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPSite MySite
        {
            Url                         = "http://$siteCollectionHostName/sites/my"
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
            MySiteHostLocation  = "http://$siteCollectionHostName/sites/my"
            ProfileDBName       = "SP_UserProfiles"
            SocialDBName        = "SP_Social"
            SyncDBName          = "SP_ProfileSync"
            EnableNetBIOS       = $false
            FarmAccount         = $SPFarmAccountCredential
            InstallAccount      = $SPInstallAccountCredential
            DependsOn           = @("[SPServiceAppPool]SharePointServicesAppPool","[SPSite]MySite")
        }

        SPVisioServiceApp VisioServices
        {
            Name            = "Visio Graphics Service"
            ApplicationPool = "SharePoint Services App Pool"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        }

        SPWordAutomationServiceApp WordAutomation 
        { 
            Name            = "Word Automation Service" 
            Ensure          = "Present"
            ApplicationPool = "SharePoint Services App Pool"
            InstallAccount  = $SPInstallAccountCredential
            DependsOn       = "[SPServiceAppPool]SharePointServicesAppPool"
        } 
    }
}
$configParameters = Import-PowershellDataFile configparemeters.psd1;
$SP2016EntDevMachineName = $configParameters.SP2016EntDevMachineName
$configurationData = @{ AllNodes = @(
    @{ NodeName = $SP2016EntDevMachineName; PSDscAllowPlainTextPassword = $True }
) }
SP2016EntDevEnv -ConfigurationData $configurationData -ConfigParameters $configParameters

