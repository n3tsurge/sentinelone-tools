<#

.SYNOPSIS
This powershell script helps sysadmins determine which exclusion in SentinelOne may be wrong

.DESCRIPTION
This powershell script helps sysadmins determine which exclusion in SentinelOne may be wrong

.EXAMPLE
Test-SentinelOneExclusion -CheckPath C:\users\myuser\Download\myfile.exe -ApiToken abcdef -TenantUrl mytenant.sentinelone.net

.LINK
http://github.com/zerooonesec/sentinelone-tools

#>

<# 
Grabs all the exclusions for a given site id
#>
function Get-Exclusions {

    Param(
        [Parameter(Mandatory=$true)][string]$ApiToken,
        [Parameter(Mandatory=$true)][string]$TenantUrl,
        [Parameter(Mandatory=$false)][string]$SiteId,
        [Parameter(Mandatory=$false)][string]$GroupId
    )

    $sideIds
    
    # Set a Request Parameter object for Invoke-RestMethod
    $RequestParameters = @{}
    $RequestParameters.Headers = @{Authorization="ApiToken "+$ApiToken}
    $RequestParameters.ContentType = 'application/json'
    if($SiteId) {
        $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/exclusions?limit=100&type=path&siteIds=$siteId"
    } elseif ($GroupId) {
        $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/exclusions?limit=100&type=path&groupIds=$GroupId"
    }
    $RequestParameters.Method = 'GET'

    # Create an empty set of exclusions
    $exclusions = @()

    # Pull the initial set of exclusions
    $response = Invoke-RestMethod @RequestParameters

    # Store the initial set of exclusions
    if($response.data) {
        $exclusions += $response.data
    }

    # If there is another page of items, pull them and continue to do so until
    # there are none left
    $completeDataSet = $false
    if($response.pagination.nextCursor) {

        while(!$completeDataSet) {

            # Grab the next cursor
            $cursor = $response.pagination.nextCursor

            if($SiteId) {
                $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/exclusions?limit=100&type=path&siteIds=$siteId&cursor=$cursor"
            } elseif ($GroupId) {
                $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/exclusions?limit=100&type=path&groupIds=$GroupId&cursor=$cursor"
            }
            
            $response = Invoke-RestMethod @RequestParameters
            
            # Check to see if we have more data
            if($response.data) {

                $exclusions += $response.data
                # If there is a new cursor grab it
                # if not, break the loop
                if($response.pagination.nextCursor) {
                    $cursor = $response.pagination.nextCursor
                } else {
                    $completeDataSet = $true
                }
            }
        }
    }

    return $exclusions

}

<#
Pulls a list of site IDs
#>
function Get-Sites {

    Param(
        [Parameter(Mandatory=$true)][string]$ApiToken,
        [Parameter(Mandatory=$true)][string]$TenantUrl
    )

    # Set a Request Parameter object for Invoke-RestMethod
    $RequestParameters = @{}
    $RequestParameters.Headers = @{Authorization="ApiToken "+$ApiToken}
    $RequestParameters.ContentType = 'application/json'
    $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/sites"
    $RequestParameters.Method = 'GET'

    # Create an empty set of sites
    $sites = @()

    # Pull the initial set of sites
    $response = Invoke-RestMethod @RequestParameters

    if($response.data) {
        $sites = $response.data
    }

    return $sites
}

<#
Pulls a list of group IDs
#>
function Get-Groups {

    Param(
        [Parameter(Mandatory=$true)][string]$ApiToken,
        [Parameter(Mandatory=$true)][string]$TenantUrl
    )

    # Set a Request Parameter object for Invoke-RestMethod
    $RequestParameters = @{}
    $RequestParameters.Headers = @{Authorization="ApiToken "+$ApiToken}
    $RequestParameters.ContentType = 'application/json'
    $RequestParameters.Uri = "https://$TenantUrl/web/api/v2.0/groups?limit=100&countOnly=false"
    $RequestParameters.Method = 'GET'

    # Create an empty set of groups
    $groups = @()

    # Pull the initial set of sites
    $response = Invoke-RestMethod @RequestParameters

    if($response.data) {
        $groups = $response.data
    }

    return $groups
}

function Test-SentinelOneExclusion {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$ApiToken,
        [Parameter(Mandatory=$true)][string]$TenantUrl,
        [Parameter(Mandatory=$true)][string]$CheckPath
    )

    # Fetch a list of siteIds and groupIds
    Write-Host "[*] Fetching Site IDs"
    $SiteIds = (Get-Sites -ApiToken $ApiToken -TenantUrl $TenantUrl).sites.id
    Write-Host "[*] Fetching Group IDs"
    $GroupIds = (Get-Groups -ApiToken $ApiToken -TenantUrl $TenantUrl).id

    # Get the site level exclusions
    Write-Host "[*] Fetching all Site Exclusions"
    ForEach ($SiteId in $SiteIds) {
        $exclusions += (Get-Exclusions -ApiToken $ApiToken -TenantUrl $TenantUrl -SiteId $SiteId)
    }

    # Get all group level exclusions
    Write-Host "[*] Fetching all Group Exclusions"
    ForEach ($GroupId in $GroupIds) {
        $exclusions += (Get-Exclusions -ApiToken $ApiToken -TenantUrl $TenantUrl -GroupId $GroupId)
    }

    #$exclusions = $exclusions | Select-Object value,pathExclusionType,mode,type,scopeName,scope -Unique
    $paths = $exclusions | Select-Object value -Unique

    $matchingExclusions = @()

    Write-Host "[*] Checking $($exclusions.Count) Exclusions"    
    $paths | ForEach-Object {
        $origPath = $_.value
        $path = $origPath
        $path = $path -replace "\\","\\"
        $path = $path -replace "\*",".*"
        $path = $path -replace ":","\:"
        $path = $path -replace "\\\\Device\\\\HarddiskVolume\d+","^.*"
        $path = $path -replace "\\\\Device\\\\Mup","^.*"
        $path = $path -replace " ","\s"
        if($_.pathExclusionType -eq "subfolders") {
            $path = $path+".*$"
        }
        if($CheckPath -match $path) {
            Write-Host "[*] Found a match"
            $exclusion = $exclusions | ? { $_.value -eq $origPath }
            $matchingExclusions += $exclusion
        }
    }

    Write-Host "[*] Displaying all matching exclusions"
    $matchingExclusions | ft id, description, value, scopeName, mode, pathExclusionType, userName
}

