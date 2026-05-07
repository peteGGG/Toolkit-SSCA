    <# 
    .SYNOPSIS
        Collects asset related information about Active Directory domains as part of a SOC SIEM Coverage Assessment.   

    .DESCRIPTION 
        Utilises Active Directory Remote Server Administation Tools to collect a list of domain assets for SOC SIEM Coverage Assessment (SSCA). Exports it to a standard format to ensure that Data structure is consistent.

    .PARAMETER Collect
        Collect asset related data from a target domain. (This is the first Phase required by the script.  Run this for each domain you have)

    .PARAMETER Collate
        Collate collected asset related Active Directory data into a compliant format. (This is the second phase required by the script.  Run this after you have collected all domain data)

    .PARAMETER Target
        Fully qualified domain name of the target domain controller or domain to be queried.

    .PARAMETER In
        The input directory checked by the script to retrieve collected data files. Defaults to the current working directory.

    .PARAMETER Out
        The output directory where the collated data will be saved. Defaults to the current working directory.
    
    .EXAMPLE
        .\Get-ADDomainAssets.ps1 -Collect
        .\Get-ADDomainAssets.ps1 -Collect -Target 'example.com' -Out '.\OUTPUT_DIR\'
        .\Get-ADDomainAssets.ps1 -Collate
        .\Get-ADDomainAssets.ps1 -Collate -In '.\COLLECTION_DIR\' -Out '.\OUTPUT_DIR\'

    .NOTES
        Version : 2025.11
        Last Updated: 3 November 2025

#> 


<#PSScriptInfo

    .VERSION 2025.11

    .GUID 5b916390-1823-4469-8723-1dda863ec9e4

#>

#requires -Version 5.0
#Requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $false, DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Collect', HelpMessage = 'Collect asset related Active Directory data from a target domain')]
    [switch] $Collect,
    [Parameter(Mandatory = $false, ParameterSetName = 'Collect', HelpMessage = 'Fully qualified domain name of the target domain controller or domain to be queried')]
    [string] $Target = $null,
    [Parameter(Mandatory = $true, ParameterSetName = 'Collate', HelpMessage = 'Collate collected asset related Active Directory data into a compliant format')]
    [switch] $Collate,
    [Parameter(Mandatory = $false, ParameterSetName = 'Collate', HelpMessage = 'The directory where asset files will be retrieved for collation into a single asset list')]
    [string] $In = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'The directory where results will be saved')]
    [string] $Out = '.'
    )
    
function Verify-Domain {

    Write-Host ("Verifying target domain")
    try {
        $Domain = (Get-ADDomain -Server $Target)
        Write-Host ("Connected to domain $($Domain.DNSRoot)")
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
    $Domain.DNSRoot
}

function Get-DomainControllers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )

    Write-Host ("Finding domain controllers")
    $results = @()
    try {
        $DCs = Get-ADDomainController -Filter * -Server $Target
        @($DCs | ForEach-Object {

            # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
            $object = New-Object -TypeName psobject
            $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ($_.HostName).ToLower()
            $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($TargetDomain).ToLower()
            $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "DCs"
            $results += $object
            
            Write-Host ("`t+ $($_.HostName)")
        }) 
        $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath ("SSCA_COLLECT_{0}_0_DCs.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}

function Get-TrustedDomains {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $results = @()
    Write-Host ("Finding trusted domains")
    try {
        $TrustedDomains = Get-ADTrust -Filter "ObjectClass -eq 'trustedDomain' -and TrustType -eq 'Uplevel' -and Direction -eq 'Outbound'" -Server $Target
        @($TrustedDomains | ForEach-Object {
            
            # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
            $object = New-Object -TypeName psobject
            $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($_.Name).ToLower()
            $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "TrustedDomains"
            $results += $object

            Write-Host ("`t+ $($_.Name)")
        }) 
    $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_X_TrustedDomains.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-ADFSServers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $results = @()
    Write-Host ("Finding ADFS servers")
    try {
        $ADFSGroups = Get-ADGroup -Filter "Name -like '*adfs*'" -Server $Target
        @($ADFSGroups | ForEach-Object {
            try {
                $ADFSServers = Get-ADGroupMember -Identity $_.Name -Server $Target | Where-Object { $_.objectClass -eq 'computer' } | Select-Object -ExpandProperty DistinguishedName
            
                @($ADFSServers | ForEach-Object {
                    $Domain = ($_.Substring($_.IndexOf("DC=")) -split ",").Trim("DC=") -join "."
                    $HostName = $_.Split(",")[0].Trim("CN=")

                    # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
                    $object = New-Object -TypeName psobject
                    $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ("{0}.{1}" -f $HostName, $Domain).ToLower()
                    $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($Domain).ToLower()
                    $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "ADFS"
                    $results += $object

                    Write-Host ("`t+ {0}.{1}." -f $HostName, $Domain)
                })
            } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") } 
        }) 
    $results| Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_1_ADFS.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-ADCSServers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $results = @()
    Write-Host ("Finding ADCS servers")
    try {
        $CertPublishersSID = $((Get-ADDomain -Server $Target).DomainSID.Value + "-517")
        $CAServers = Get-ADGroupMember -Server $Target -Identity $CertPublishersSID -ErrorAction Stop | Where-Object { $_.objectClass -eq 'computer' }
        @($CAServers | ForEach-Object {
            try {
                $caComputer = Get-ADComputer -Identity $_ -Server $Target -Properties DNSHostName -ErrorAction SilentlyContinue

                # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
                $object = New-Object -TypeName psobject
                $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ($caComputer.DNSHostName).ToLower()
                $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($TargetDomain).ToLower()
                $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "ADCS"
                $results += $object

                Write-Host ("`t+ $($caComputer.DNSHostName)")
            } catch { Write-Host ("$($_.Exception.Message)") }
        }) 
        $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_2_ADCS.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-EntraConnectServers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )

    Write-Host ("Finding Entra Connect servers")
    try {
        # Create Results Array
        $results = @()

        # Find Using the Group Name
        $EntraConnectGroups = Get-ADGroup -Filter "Name -like '*AAD*Connect*' -or Name -like '*Entra*Connect*'" -Server $Target
        
        @($EntraConnectGroups | ForEach-Object {
            try {
                $EntraConnectServers = Get-ADGroupMember -Identity $_.Name -Server $Target | Where-Object { $_.objectClass -eq 'computer' } | Select-Object -ExpandProperty DistinguishedName
                @($EntraConnectServers | ForEach-Object {
                    $Domain = ($_.Substring($_.IndexOf("DC=")) -split ",").Trim("DC=") -join "."
                    $HostName = $_.Split(",")[0].TrimStart("CN=")

                    # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
                    $object = New-Object -TypeName psobject
                    $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ("{0}.{1}" -f $HostName, $Domain).ToLower()
                    $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($Domain).ToLower()
                    $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "EntraConnect"
                    $results += $object

                    Write-Host ("`t+ {0}.{1}." -f $HostName, $Domain)
                })
            } catch { Write-Host ("$($_.Exception.Message)") } 
        })


        # Find User MSOL accounts
        $msolAccounts = Get-ADUser -Filter { (SamAccountName -like "MSOL_*") -and (Enabled -eq $true ) } -Properties Description,pwdLastSet,lastLogon

        # Use regex to extract the text after "running on computer " and before " configured"
    
        @($msolAccounts | ForEach-Object {
            try {
                    # Use regex to extract the text after "running on computer " and before " configured"
                    if ($_.Description -match "running on computer\s+([^\s]+)\s+configured") {
                        $EntraConnectServers = Get-ADComputer -Identity $Matches[1] -Server $Target | Select-Object DistinguishedName -First 1 

                        @($EntraConnectServers | ForEach-Object {
                            $Domain = ($_.DistinguishedName.Substring($_.DistinguishedName.IndexOf("DC=")) -split ",").Trim("DC=") -join "."
                            $HostName = $_.DistinguishedName.Split(",")[0].TrimStart("CN=")
                            
                            # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
                            $object = New-Object -TypeName psobject
                            $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ("{0}.{1}" -f $HostName, $Domain).ToLower()
                            $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($Domain).ToLower()
                            $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "EntraConnect"
                            $results += $object
                            
                            Write-Host ("`t+ {0}.{1}." -f $HostName, $Domain)
                        })
                    }

            } Catch { Write-Host ("$($_.Exception.Message)") } 

        })      
    
        $results   | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_3_EntraConnect.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-TrustedForDelegationServers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )

    Write-Host ("Finding servers trusted for delegation")
    try {
        #$DateThreshold = (Get-Date).AddDays(-31)
        $TrustedForDelegation = Get-ADComputer -Filter 'TrustedForDelegation -eq "True" -and Enabled -eq "True" -and PasswordLastSet -gt $DateThreshold' -Server $Target -Properties DNSHostName, TrustedForDelegation
        $results = @()
        @($TrustedForDelegation | ForEach-Object {
            $Computer = $_.DNSHostName
            try {
                # Ignore Domain Controllers
                Get-ADDomainController -Identity $Computer -Server $Target | Out-Null
            } catch {

                # Create Custom PSObject (Compatible with PowerShell Constrained Language Mode)
                $object = New-Object -TypeName psobject
                $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ($Computer).ToLower()
                $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($TargetDomain).ToLower()
                $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "TrustedForDelegation"
                $results += $object

                Write-Host ("`t+ $($Computer)")
            }})
        $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_4_TrustedForDelegation.csv" -f $TargetDomain.toUpper()))
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-WindowsServers {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $results = @()
    Write-Host ("Finding Windows servers")
    try {
        #$DateThreshold = (Get-Date).AddDays(-31)
        $WindowsServers = Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server*" -and Enabled -eq "True" -and PasswordLastSet -gt $DateThreshold' -Server $Target -Properties DNSHostName, PasswordLastSet, OperatingSystem | Where-Object { $_.DistinguishedName -notlike "*OU=Domain Controllers,*" }
        @($WindowsServers | ForEach-Object {

            $object = New-Object -TypeName psobject
            $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ($_.DNSHostName).ToLower()
            $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($TargetDomain).ToLower()
            $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "Servers"
            $results += $object

            Write-Host ("`t+ $($_.DNSHostName)")    
        }) 
        $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_5_Servers.csv" -f $TargetDomain.toUpper()))
        Write-Host ("Found {0} Windows servers" -f ($WindowsServers | Measure-Object).Count)
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}


function Get-WindowsEndPoints {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $results = @()
    Write-Host ("Finding Windows endpoints")
    try {
        #$DateThreshold = (Get-Date).AddDays(-31)
        $WindowsEndPoints = Get-ADComputer -Filter 'Enabled -eq "True" -and PasswordLastSet -gt $DateThreshold' -Server $Target -Properties DNSHostName, PasswordLastSet, OperatingSystem | Where-Object { $_.OperatingSystem -match "Windows [^S]" }
        @($WindowsEndpoints | ForEach-Object {
            
            $object = New-Object -TypeName psobject
            $object | Add-Member -Name 'FQDN' -MemberType NoteProperty -Value ($_.DNSHostName).ToLower()
            $object | Add-Member -Name 'ADDOMAIN' -MemberType NoteProperty -Value ($TargetDomain).ToLower()
            $object | Add-Member -Name 'ASSETGROUP' -MemberType NoteProperty -Value "Endpoints"
            $results += $object

            Write-Host ("`t+ $($_.DNSHostName)") 
        }) 
        $results | Export-Csv -NoTypeInformation -Path (Join-Path -Path $Path -ChildPath (".\SSCA_COLLECT_{0}_6_Endpoints.csv" -f $TargetDomain.toUpper()))
        Write-Host ("Found {0} Windows endpoints" -f ($WindowsEndpoints | Measure-Object).Count)
    } catch { Write-Host -ForegroundColor Red ("ERROR: $($_.Exception.Message)") }
}

function Collate {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Output
    )

    Write-Host ("Collating files found in path '{0}'" -f $Path)

    $data = Get-ChildItem -Path $Path | Where-Object { $_.Name -like "SSCA_COLLECT*" } | ForEach-Object { 
        Write-Host "Processing $_"
        Import-Csv -Path $_.Name 
    } | Sort-Object ASSETGROUP, FQDN, ADDOMAIN -Unique

    Write-Host ("Finding trusted domain controllers")
    $data | Where-Object { $_.ASSETGROUP -eq "TrustedDomains" } | ForEach-Object { 
        $global:FoundDCs = $false
        $TrustedDomain = $_.ADDOMAIN 
        $data | Where-Object { $_.ADDOMAIN -eq $TrustedDomain -and $_.ASSETGROUP -eq "DCs"} | ForEach-Object {
            $global:FoundDCs = $true
            $data += [pscustomobject]@{
                    FQDN = $_.FQDN
                    ADDOMAIN = $_.ADDOMAIN
                    ASSETGROUP = "TrustedDCs"
            }
            Write-Host ("`t+ $($_.FQDN).") 
        }
         if (-not $global:FoundDCs) {
            Write-Host -ForegroundColor Red ("WARNING: Domain Controllers for Trusted Domain {0} not found, ensure all relevant data has been collected and re-run collation if necessary." -f $TrustedDomain)
        }
    }

    $outputFile = Join-Path $Output -ChildPath "ssca_lookup.csv"
    Write-Host("Saving collated data to {0}" -f $outputFile)
    
    @($data | Export-Csv -NoTypeInformation -Path $outputFile)
}

#region Main

If($Collect) {
    if (-not $Target) { $Target = $env:USERDNSDOMAIN }

    if (-not $DaysInactive) {$DateThreshold = (Get-Date).AddDays(-30)}

    $TargetDomain = Verify-Domain
    if($TargetDomain) {
        Get-DomainControllers -Path $Out
        Get-TrustedDomains -Path $Out
        Get-ADFSServers -Path $Out
        Get-ADCSServers -Path $Out
        Get-EntraConnectServers -Path $Out
        Get-TrustedForDelegationServers -Path $Out
        Get-WindowsServers -Path $Out
        Get-WindowsEndPoints -Path $Out
    } else {
        Write-Host -ForegroundColor Red ("ERROR: Failed to run Get-ADDomainAssets.ps1. Unable to verify the target {0}." -f $Target)
    }
} Elseif($Collate) {
    Collate -Path $In -Output $Out
} else {
    Write-Host -Foregroundcolor Red ("ERROR: A script function must be specified, ensure the -Collect or -Collate flag is provided during execution.")
}






