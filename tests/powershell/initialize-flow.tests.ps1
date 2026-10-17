param([string]$SourceRoot)
$ErrorActionPreference = 'Stop'
$Tokens = $null; $ParseErrors = $null
$File = Join-Path $SourceRoot 'deploy/lan-stage1/department-device/Initialize-OrbitWsl.ps1'
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count -ne 0) { throw ($ParseErrors | Out-String) }
# Execute the exact production control-flow function, without running its outer
# command-line entrypoint. Only platform and HTTP/WSL adapters below are fakes.
$Function = $Ast.Find({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Invoke-OrbitWslInitialization' }, $false)
. ([scriptblock]::Create($Function.Extent.Text))
$Temp = Join-Path ([IO.Path]::GetTempPath()) ('orbit-initialize-test-' + [guid]::NewGuid().ToString('N'))
$Bundle = Join-Path $Temp 'bundle'
New-Item -ItemType Directory -Path $Bundle | Out-Null
New-PSDrive -Name D -PSProvider FileSystem -Root $Temp | Out-Null
$global:ExpectedRegistryLocation = Join-Path 'D:\OrbitCockpit\runtime' 'OrbitRuntime-Ubuntu-22.04'
$Files = @('OrbitFirstInstall.ps1', 'docker-bootstrap.lock.json', 'versions.env', 'wsl/bootstrap-root.sh', 'wsl/repair-rootless-docker.sh', 'wsl/prepare-docker-from-lan.py')
$Rows = @()
foreach ($Name in $Files) {
    $Destination = Join-Path $Bundle $Name
    New-Item -ItemType Directory -Force -Path (Split-Path $Destination -Parent) | Out-Null
    Copy-Item (Join-Path $SourceRoot "deploy/lan-stage1/department-device/$Name") $Destination
    $Rows += @{path=$Name;sha256='sha256:' + (Get-FileHash $Destination -Algorithm SHA256).Hash.ToLowerInvariant()}
}
'SYNTHETIC PUBLIC CA' | Set-Content (Join-Path $Bundle 'orbit-human-ca.pem')
$Rows += @{path='orbit-human-ca.pem';sha256='sha256:' + (Get-FileHash (Join-Path $Bundle 'orbit-human-ca.pem') -Algorithm SHA256).Hash.ToLowerInvariant()}
@{schema_version='orbit.department-device-pilot-artifact-set/0.1';contains_secret=$false;production_authorization=$false;release_authorization=$false;files=$Rows} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Bundle 'artifact-set-manifest.json')
$global:DeliveryText = Get-Content (Join-Path $SourceRoot 'tests/fixtures/department-first-install/docker-jammy-amd64-offline.json') -Raw
$global:FlowTrace = [Collections.Generic.List[string]]::new()
function global:Assert-OrbitWindowsAdministrator { $global:FlowTrace.Add('admin-adapter') }
function global:Invoke-WebRequest {
    $global:FlowTrace.Add('http-manifest')
    if ($global:FlowScenario -eq 'html') { return @{Headers=@{'Content-Type'='text/html'};Content='<html/>'} }
    return @{Headers=@{'Content-Type'='application/json'};Content=$global:DeliveryText}
}
function global:Get-ChildItem {
    param([string]$Path)
    if ($Path -ne 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss') { throw 'unexpected_registry_read' }
    $global:FlowTrace.Add('registry-location')
    'synthetic-registry-entry'
}
function global:Get-ItemProperty {
    process { [pscustomobject]@{DistributionName='OrbitRuntime-Ubuntu-22.04';Version=2;BasePath=$global:ExpectedRegistryLocation} }
}
function global:Start-Sleep { param($Seconds) $global:FlowTrace.Add('restart-wait-adapter') }
function global:wsl.exe {
    $Arguments = @($args | ForEach-Object { [string]$_ })
    $global:LASTEXITCODE = 0
    if ($Arguments[0] -eq '--list') {
        $global:FlowTrace.Add('list')
        if ($global:DistroPresent) { 'OrbitRuntime-Ubuntu-22.04' }
        return
    }
    if ($Arguments[0] -eq '--help') {
        $global:FlowTrace.Add('help')
        "    --install [Options]`n        --name <Name>`n        --location <Path>`n        --no-launch`n    --list"
        return
    }
    if ($Arguments[0] -eq '--install') {
        $global:FlowTrace.Add('install-distro')
        if ($Arguments -notcontains '--location' -or $Arguments -notcontains $global:ExpectedRegistryLocation) { throw 'missing_fixed_location' }
        $global:DistroPresent = $true
        return
    }
    if ($Arguments[0] -eq '--terminate') { $global:FlowTrace.Add('terminate'); return }
    if ($Arguments[0] -notin @('-d', '--distribution') -or $Arguments[1] -ne 'OrbitRuntime-Ubuntu-22.04') { throw 'unexpected_distribution_or_command' }
    if ($Arguments -contains '/usr/bin/test') {
        $global:FlowTrace.Add('identity-check')
        $global:LASTEXITCODE = 1
        if ($global:FlowScenario -eq 'registered') { $global:LASTEXITCODE = 0 }
        return
    }
    if ($Arguments -contains '-s') {
        $ScriptText = ($input | Out-String)
        $Target = [regex]::Match($ScriptText, "(?m)^target='([^']+)'$").Groups[1].Value
        $Payload = [regex]::Match($ScriptText, "(?m)^base64 -d > .+ <<'__ORBIT_PAYLOAD_END__'\n([A-Za-z0-9+/=]+)\n__ORBIT_PAYLOAD_END__").Groups[1].Value
        $Expected = [regex]::Match($ScriptText, "'([a-f0-9]{64})'").Groups[1].Value
        if (-not $Target -or -not $Payload -or -not $Expected -or $ScriptText -match '\r') { throw 'copy_stdin_transport_drift' }
        $Bytes = [Convert]::FromBase64String($Payload)
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try { $Digest = $Hasher.ComputeHash($Bytes) } finally { $Hasher.Dispose() }
        $Actual = ([BitConverter]::ToString($Digest)).Replace('-', '').ToLowerInvariant()
        if ($Actual -ne $Expected) { throw 'copy_payload_digest_drift' }
        $global:FlowTrace.Add('copy:' + $Target)
        return
    }
    if ($Arguments -contains 'prepare-base') { $global:FlowTrace.Add('prepare-base'); return }
    if ($Arguments -contains '/opt/orbit-bootstrap/prepare-docker-from-lan.py') { $global:FlowTrace.Add('verify-frozen-package'); return }
    if ($Arguments -contains '/opt/orbit-offline/bundle/install-docker-offline.sh') { $global:FlowTrace.Add('install-frozen-package'); return }
    if ($Arguments -contains 'finish') { $global:FlowTrace.Add('finish'); return }
    if ($Arguments -contains '/opt/orbit-bootstrap/repair-rootless-docker.sh') { $global:FlowTrace.Add('user-session'); return }
    throw 'unexpected_native_command'
}
function Assert-Sequence($Actual, $Expected) {
    $Previous = -1
    foreach ($Event in $Expected) {
        $Position = $Actual.IndexOf($Event)
        if ($Position -le $Previous) { throw "wrong_phase_order:$Event" }
        $Previous = $Position
    }
}
$Results = @()
try {
    foreach ($Scenario in @('fresh', 'resume', 'html', 'registered')) {
        $global:FlowScenario=$Scenario
        $global:DistroPresent=$Scenario -ne 'fresh'
        $global:FlowTrace.Clear()
        $Failure=$null
        try { Invoke-OrbitWslInitialization -BundleRoot $Bundle -Install -Confirm:$false }
        catch { $Failure=$_.Exception.Message }
        if ($Scenario -eq 'html') {
            if ($Failure -notlike '*docker_delivery_not_json*' -or $global:FlowTrace.Contains('list')) { throw "html_did_not_stop_before_wsl:$Failure" }
        } elseif ($Scenario -eq 'registered') {
            if ($Failure -notlike '*existing_runner_identity_requires_review*' -or @($global:FlowTrace | Where-Object { $_ -like 'copy:*' }).Count -ne 0) { throw "registered_identity_not_protected:$Failure" }
        } else {
            if ($Failure) { throw "positive_flow_failed:$Failure" }
            Assert-Sequence $global:FlowTrace @('http-manifest','list','registry-location','identity-check','copy:/opt/orbit-offline/orbit-human-ca.pem','prepare-base','verify-frozen-package','install-frozen-package','terminate','finish','user-session')
            if (($Scenario -eq 'fresh') -ne $global:FlowTrace.Contains('install-distro')) { throw 'unexpected_install_on_resume' }
        }
        $Results += @{scenario=$Scenario;status='passed';trace=@($global:FlowTrace)}
    }
    $Results | ConvertTo-Json -Depth 5
    Write-Host 'FINAL: 4 production Initialize control-flow scenarios passed with synthetic OS/network adapters.'
} finally {
    foreach ($Name in @('Assert-OrbitWindowsAdministrator','Invoke-WebRequest','Get-ChildItem','Get-ItemProperty','Start-Sleep','wsl.exe')) { Remove-Item "function:$Name" }
    Remove-PSDrive D
    Remove-Item $Temp -Recurse -Force
}

