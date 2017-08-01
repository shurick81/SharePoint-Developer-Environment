Configuration SharePointDevelopmentEnvironmentTest
{
    param(
        [String]
        $DomainName = "lab3.local",

        [String]
        $DCMachineName = "lab3dc3",

        [String]
        $SP2016DevMachineName = "lab3sp1",

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
        $SPAdminGroupName = "SP Admins",

        [String]
        $SPMemberGroupName = "SP Members",

        [String]
        $SPVisitorGroupName = "SP Visitors"
    )

    # examining, generatig and requesting credentials
        if ( !$DomainAdminCredential )
        {
            if ( $domainAdminUserName )
            {
                $securedPassword = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
                $domainAdminCredential = New-Object System.Management.Automation.PSCredential( $domainAdminUserName, $securedPassword )
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

        $SPOCAccountPass = ConvertTo-SecureString "Any3ligiblePa`$`$" -AsPlainText -Force
        $SPOCAccountCredential = New-Object System.Management.Automation.PSCredential( "anyusername", $SPOCAccountPass )

    # credentials are ready

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory

    Node $DCMachineName
    {
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
            DependsOn                       = "[WindowsFeatureSet]DomainFeatures"
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
            UserName    = $SPInstallAccountCredential.UserName
            Password    = $SPInstallAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPFarmAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPFarmAccountCredential.UserName
            Password    = $SPFarmAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPWebAppPoolAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPWebAppPoolAccountCredential.UserName
            Password    = $SPWebAppPoolAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPSearchServiceAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPSearchServiceAccountCredential.UserName
            Password    = $SPSearchServiceAccountCredential
            DependsOn   = "[xWaitForADDomain]WaitForDomain"
        }

        xADUser SPCrawlerAccountUser
        {
            DomainName  = $DomainName
            UserName    = $SPCrawlerAccountCredential.UserName
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

        xADGroup ExampleGroup
        {
            GroupName           = "SPAdmins"
            Ensure              = 'Present'
            MembersToInclude    = { $SPInstallAccountCredential.UserName }
            DependsOn           = "[xADUser]SPInstallAccountUser"
        }
    }

}

#SharePointDevEnvTest11 -ConfigurationData @{ AllNodes = @( @{ NodeName = "lab3dc2"; PSDscAllowPlainTextPassword = $True } ) }