[CmdletBinding()]

Param(
    [Parameter(Mandatory=$true)][string]$domain = "mydomain.com"
)

Write-Verbose "[-] Getting the NETBIOS name of the domain $domain"
$netBIOSName = (Get-ADDomain $domain).NetBIOSName

Write-Verbose "[-] Collecting Agent Information from Sentinel One"
$managedComputers = Get-S1Agents -ProxyUseDefaultCredentials -Limit 1000 -Domain $netBIOSName
Write-Verbose "[-] Found $($managedComputers.Length) computers in SentinelOne"

Write-Verbose "[-] Collecting Windows Computer Information from Active Directory"
$computers = Get-ADComputer -Filter { OperatingSystem -notlike "*server*" -and Enabled -eq $true } -Server $domain -Property OperatingSystem, Modified | Where { $_.Modified -gt (Get-Date).AddMonths(-1) } | Select-Object Name, OperatingSystem
Write-Verbose "[-] Found $($computers.Length) computers in Active Directory"

Write-Verbose "[-] Searching for unmanaged machines"
$computers | % { 
    $_ | Add-Member "Managed" $null; 
    if($managedComputers.network_information.computer_name -contains $_.Name) { 
        $_.Managed = $true 
    } else { 
        $_.Managed = $false 
    } 
}

$computers | Export-CSV "$($domain)-managedvsunmanaged.csv" -NoTypeInformation 
