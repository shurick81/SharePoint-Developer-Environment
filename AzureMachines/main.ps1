Configuration SharePointDevelopmentEnvironment
{
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $DomainName = "bizspark-sap2.local",

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $DomainAdmin,

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
    $SPDevNodes = ( $AllNodes | ? { $_.Role -contains "Search" } ).NodeName;

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
