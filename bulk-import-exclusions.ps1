$siteId = ""
$groupId = ""
$apiToken = ""
$exclusions = Import-CSV 'C:\Users\zeroonesec\Downloads\S1 Exchange Exclusions.csv'
$tenant = ""

# Base Request
$baseRequest = @{
    filter=  @{
        siteIds = @(
            $siteId
            );
        groupIds = @(
            $groupId
            );
        tenant = $true;
    };
    data = @{
        description = "Exchange Exclusion";
        value = "test2";
        osType = "windows";
        type = "path";
        pathExclusionType = "subfolders";
        mode = "disable_all_monitors_deep";
    };
}


$exclusions | % {

    $request = $baseRequest

    if($_.Implement -eq 'Y') {
    
        if($_.Type -eq "Folder") {
            $request.data.type = "path"
            $request.data.pathExclusionType = "subfolders"
        }

        if($_.Type -eq "File") {
            $request.data.type = "path"
            $request.data.pathExclusionType = "file"
        }

        if($_.Type -eq "Extension") {
            $request.data.type = "file_type"
            $request.data.Remove('pathExclusionType')
        }

        $request.data.value = $_."Exclusion Path"

        $request | ConvertTo-Json

        Invoke-RestMethod -Method POST -Uri https://$tenant.sentinelone.net/web/api/v2.0/exclusions -Body ($request | ConvertTo-Json) -ContentType application/json -Headers @{Authorization = "ApiToken $apiToken"}
    }
}
