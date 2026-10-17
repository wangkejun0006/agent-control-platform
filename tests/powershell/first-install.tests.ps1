param([string]$SourceRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $SourceRoot 'deploy/lan-stage1/department-device/OrbitFirstInstall.ps1')
function Assert-True($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Assert-Rejected([scriptblock]$Call, [string]$Reason) {
    try { & $Call; throw 'expected_rejection_missing' } catch {
        if ($_.Exception.Message -notlike "*$Reason*") { throw }
    }
}
$global:TestCount = 0
function Case([string]$Name, [scriptblock]$Call) { & $Call; $global:TestCount++; Write-Host "PASS $Name" }
Case 'unrelated --name must not qualify install' {
    $HelpText = "    --install [Options]`n        --no-launch`n    --mount <Disk>`n        --name <Name>`n        --location <Path>"
    Assert-True (-not (Test-OrbitNativeInstallOptions $HelpText)) 'wrong_subcommand_accepted'
}
Case 'missing location rejected' {
    Assert-True (-not (Test-OrbitNativeInstallOptions "    --install`n        --name <Name>`n        --no-launch")) 'missing_location_accepted'
}
Case 'install scoped complete options accepted' {
    Assert-True (Test-OrbitNativeInstallOptions "    --install [Options]`n        --name <Name>`n        --location <Path>`n        --no-launch`n    --list") 'valid_install_rejected'
}
Case 'translated text retains token semantics' {
    Assert-True (Test-OrbitNativeInstallOptions "    --install <发行版>`n        --name <名称>`n        --location <位置>`n        --no-launch`n    --list") 'translated_install_rejected'
}
Case 'existing runner identity stops before mutation' {
    function global:wsl.exe { $global:LASTEXITCODE = 0 }
    Assert-Rejected { Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04' } 'existing_runner_identity_requires_review'
}
Case 'WSL error is not empty identity' {
    function global:wsl.exe { $global:LASTEXITCODE = 2 }
    Assert-Rejected { Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04' } 'runner_identity_preflight_failed'
}
Case 'empty identity passes' {
    $global:IdentityChecks = @()
    function global:wsl.exe {
        $global:IdentityChecks += ,@($args)
        $global:LASTEXITCODE = 1
    }
    Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04'
    Assert-True ($global:IdentityChecks.Count -eq 6) 'six_identity_predicates_required'
    foreach ($Check in $global:IdentityChecks) {
        Assert-True ($Check.Count -eq 8 -and $Check[0] -eq '--distribution' -and $Check[4] -eq '--exec' -and $Check[5] -eq '/usr/bin/test') 'shell_or_argument_drift'
    }
}
Case 'dangling identity link stops first installation' {
    function global:wsl.exe { $global:LASTEXITCODE = 1; if ($args[-2] -eq '-L') { $global:LASTEXITCODE = 0 } }
    Assert-Rejected { Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04' } 'existing_runner_identity_requires_review'
}
Case 'unexpected exit 31 is a preflight error' {
    function global:wsl.exe { $global:LASTEXITCODE = 31 }
    Assert-Rejected { Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04' } 'runner_identity_preflight_failed:31'
}
Case 'different distro rejected without native execution' {
    function global:wsl.exe { throw 'unexpected_wsl_side_effect' }
    Assert-Rejected { Assert-OrbitNoRunnerIdentity 'Ubuntu-24.04' } 'runner_distribution_scope_invalid'
}
Remove-Item function:wsl.exe
Case 'HTML from central is rejected before WSL' {
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $Temp | Out-Null
    try {
        Copy-Item (Join-Path $SourceRoot 'deploy/lan-stage1/department-device/docker-bootstrap.lock.json') $Temp
        function global:Invoke-WebRequest { return @{ Headers=@{'Content-Type'='text/html'}; Content='<html></html>' } }
        Assert-Rejected { Get-OrbitDockerDelivery $Temp } 'docker_delivery_not_json'
    } finally { Remove-Item function:Invoke-WebRequest; Remove-Item $Temp -Recurse }
}
Case 'changed manifest digest rejected' {
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $Temp | Out-Null
    try {
        Copy-Item (Join-Path $SourceRoot 'deploy/lan-stage1/department-device/docker-bootstrap.lock.json') $Temp
        function global:Invoke-WebRequest { return @{ Headers=@{'Content-Type'='application/json'}; Content='{}' } }
        Assert-Rejected { Get-OrbitDockerDelivery $Temp } 'docker_delivery_manifest_digest_mismatch'
    } finally { Remove-Item function:Invoke-WebRequest; Remove-Item $Temp -Recurse }
}
Case 'missing CA rejects without a WSL call' {
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $Temp | Out-Null
    try {
        '{"files":[]}' | Set-Content (Join-Path $Temp 'artifact-set-manifest.json')
        function global:wsl.exe { throw 'unexpected_wsl_side_effect' }
        Assert-Rejected { Copy-OrbitVerifiedBootstrapFile $Temp 'orbit-human-ca.pem' 'OrbitRuntime-Ubuntu-22.04' '/opt/orbit-offline/orbit-human-ca.pem' } 'bootstrap_file_missing_or_unlocked'
    } finally { Remove-Item function:wsl.exe; Remove-Item $Temp -Recurse }
}
Case 'changed CA rejected before copy' {
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $Temp | Out-Null
    try {
        '{"files":[{"path":"orbit-human-ca.pem","sha256":"sha256:invalid"}]}' | Set-Content (Join-Path $Temp 'artifact-set-manifest.json')
        'synthetic-public-ca' | Set-Content (Join-Path $Temp 'orbit-human-ca.pem')
        function global:wsl.exe { throw 'unexpected_wsl_side_effect' }
        Assert-Rejected { Copy-OrbitVerifiedBootstrapFile $Temp 'orbit-human-ca.pem' 'OrbitRuntime-Ubuntu-22.04' '/opt/orbit-offline/orbit-human-ca.pem' } 'bootstrap_file_digest_mismatch'
    } finally { Remove-Item function:wsl.exe; Remove-Item $Temp -Recurse }
}
Case 'copy outside explicit target rejected' {
    Assert-Rejected { Copy-OrbitVerifiedBootstrapFile '.' 'orbit-human-ca.pem' 'OrbitRuntime-Ubuntu-22.04' '/etc/hosts' } 'bootstrap_copy_scope_invalid'
}
Case 'fixed location verified against registration' {
    function global:Get-ChildItem { 'synthetic_registry_entry' }
    function global:Get-ItemProperty { process { [pscustomobject]@{ DistributionName='OrbitRuntime-Ubuntu-22.04'; Version=2; BasePath='\\?\D:\OrbitCockpit\runtime\OrbitRuntime-Ubuntu-22.04' } } }
    try { Assert-OrbitDistributionLocation 'OrbitRuntime-Ubuntu-22.04' 'D:\OrbitCockpit\runtime\OrbitRuntime-Ubuntu-22.04' }
    finally { Remove-Item function:Get-ChildItem; Remove-Item function:Get-ItemProperty }
}
Case 'same name in C drive rejected without moving it' {
    function global:Get-ChildItem { 'synthetic_registry_entry' }
    function global:Get-ItemProperty { process { [pscustomobject]@{ DistributionName='OrbitRuntime-Ubuntu-22.04'; Version=2; BasePath='C:\Users\test\wsl' } } }
    try { Assert-Rejected { Assert-OrbitDistributionLocation 'OrbitRuntime-Ubuntu-22.04' 'D:\OrbitCockpit\runtime\OrbitRuntime-Ubuntu-22.04' } 'dedicated_wsl_storage_location_mismatch' }
    finally { Remove-Item function:Get-ChildItem; Remove-Item function:Get-ItemProperty }
}
foreach ($Case in @(
    @{Id='product_center';Name='产品中心';Route='/product';Node='node_product_001'},
    @{Id='technology_center';Name='技术中心';Route='/technology';Node='node_technology_001'},
    @{Id='market_center';Name='市场中心';Route='/market';Node='node_market_001'}
)) {
    Case ('department labels and setup route: ' + $Case.Id) {
        $Config = @{schema_version='orbit.department-device-pilot/0.1';department=@{id=$Case.Id;route=$Case.Route};node=@{node_id=$Case.Node};server=@{human_origin='https://192.168.21.22:8443'};deployment_release_lock_digest='sha256:synthetic';production_authorization=$false;release_authorization=$false}
        $Manifest = @{schema_version='orbit.department-device-pilot-artifact-set/0.1';department_id=$Case.Id;node_id=$Case.Node;deployment_release_lock_digest='sha256:synthetic'}
        $View = Get-OrbitEnrollmentPresentation $Config $Manifest 'https://192.168.21.22:8443'
        Assert-True ($View.DepartmentName -eq $Case.Name) 'wrong_department_label'
        Assert-True ($View.NodeId -eq $Case.Node) 'wrong_node'
        Assert-True ($View.SetupPath -eq ($Case.Route + '/setup')) 'wrong_setup_path'
        Assert-True ($View.IdHint.Contains($Case.Route + '/setup')) 'wrong_id_hint'
        Assert-True ($View.WindowTitle.Contains($Case.Name)) 'wrong_window_title'
        Assert-True ($View.Heading.Contains($Case.Name)) 'wrong_heading'
    }
}
Case 'cross-department node cannot drive enrollment presentation' {
    $Config = @{schema_version='orbit.department-device-pilot/0.1';department=@{id='market_center';route='/market'};node=@{node_id='node_technology_001'};server=@{human_origin='https://192.168.21.22:8443'};deployment_release_lock_digest='sha256:synthetic';production_authorization=$false;release_authorization=$false}
    $Manifest = @{schema_version='orbit.department-device-pilot-artifact-set/0.1';department_id='market_center';node_id='node_technology_001';deployment_release_lock_digest='sha256:synthetic'}
    Assert-Rejected { Get-OrbitEnrollmentPresentation $Config $Manifest 'https://192.168.21.22:8443' } 'enrollment_department_scope_mismatch'
}

Write-Host "FINAL: $global:TestCount synthetic first-install checks passed; no network or WSL execution."

