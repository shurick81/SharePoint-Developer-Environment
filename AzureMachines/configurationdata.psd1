@{
    AllNodes = @(
        @{
            NodeName = "lab2dc1"
            PSDscAllowPlainTextPassword = $True
            Role = @("DC")
        },
        @{
            NodeName = "lab2sp1"
            PSDscAllowPlainTextPassword = $True
            Role = @("SPDev")
        }
    )
}