param(
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/aix')
)
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $OutputEncoding
$root = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
$scratch = Join-Path $root ('tmp/release-check-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output, $scratch | Out-Null
$checks = [Collections.Generic.List[object]]::new()
$release = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package.json') -Raw | ConvertFrom-Json
$packages = @('./cmd/agent', './cmd/gate', './internal/buildinfo', './internal/protocol')

function Invoke-Check([string]$Name, [string]$Program, [string[]]$Arguments) {
    $log = Join-Path $scratch ($Name + '.log')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    & $Program @Arguments *> $log
    $code = $LASTEXITCODE
    $checks.Add([ordered]@{name=$Name; exitCode=$code; seconds=$timer.Elapsed.TotalSeconds})
    if ($code -ne 0) {
        Select-String -LiteralPath $log -Pattern '^--- FAIL:', '^not ok ', '^# Error', '^panic:' -Context 0,12 | ForEach-Object { $_.ToString() }
        Get-Content -LiteralPath $log -Tail 35
        throw "Check failed $Name ($code), log=$log"
    }
    Write-Output "Passed $Name"
}

function Get-SourceHashes {
    $hashes = [ordered]@{}
    foreach ($name in (& git -c core.quotepath=false ls-files)) {
        if (Test-Path -LiteralPath $name -PathType Leaf) { $hashes[$name] = (Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    return $hashes
}

Push-Location $root
try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'The local release requires Windows tests' }
    $sourceCommit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the source commit' }
    $sourceDirty = [bool](& git status --porcelain --untracked-files=all)
    $sourceHashes = Get-SourceHashes
    $reportPath = Join-Path $output 'release-manifest.json'
    @{sourceCommit=$sourceCommit; sourceDirty=$sourceDirty; status='checking'; publishable=$false} | ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
    $env:GOCACHE = Join-Path $root 'tmp/go-build'
    $flags = @('WEBCODEX_BROWSER_REAL_TEST','WEBCODEX_NATIVE_REAL_TEST','WEBCODEX_LOCAL_REAL_TEST','WEBCODEX_BRIDGE_REAL_TEST','WEBCODEX_UNIVERSAL_REAL_TEST')
    foreach ($flag in $flags) { [Environment]::SetEnvironmentVariable($flag, $null, 'Process') }
    Invoke-Check 'versions' 'node' @('ai-studio-extension/sync-version.cjs','--check')
    Invoke-Check 'javascript' 'node' @('--test','--test-reporter=tap','ai-studio-extension/*.test.cjs')
    Invoke-Check 'go-tests' 'go' (@('test','-count=1') + $packages)
    Invoke-Check 'go-vet' 'go' (@('vet') + $packages)
    $agent = Join-Path $output 'webcodex-agent.exe'
    $gate = Join-Path $scratch 'webcodex-gate.exe'
    $regressionAgent = Join-Path $scratch 'webcodex-agent.exe'
    Invoke-Check 'build-agent' 'go' @('build','-trimpath','-tags','aistudio','-ldflags',('-X webcodex/internal/buildinfo.Version=' + $release.webcodexRelease.agent),'-o',$agent,'./cmd/agent')
    Invoke-Check 'build-agent-regression' 'go' @('build','-trimpath','-ldflags',('-X webcodex/internal/buildinfo.Version=' + $release.webcodexRelease.agent),'-o',$regressionAgent,'./cmd/agent')
    Invoke-Check 'go-local-tests' 'go' @('test','-tags','aistudio','./cmd/agent','./internal/buildinfo','./internal/protocol')
    Invoke-Check 'build-gate-regression' 'go' @('build','-trimpath','-ldflags',('-X webcodex/internal/buildinfo.Version=' + $release.webcodexRelease.gate),'-o',$gate,'./cmd/gate')
    Invoke-Check 'package' 'powershell' @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'package.ps1'),'-OutputDirectory',$output)
    $env:WEBCODEX_TEST_AGENT_PATH = $regressionAgent
    $env:WEBCODEX_TEST_GATE_PATH = $gate
    foreach ($flag in $flags) { [Environment]::SetEnvironmentVariable($flag, '1', 'Process') }
    Invoke-Check 'required-real-tests' 'node' @('--test','--test-reporter=tap','ai-studio-extension/*.test.cjs')
    $realLog = Get-Content -LiteralPath (Join-Path $scratch 'required-real-tests.log') -Raw
    if ($realLog -notmatch '# skipped 0\b' -or $realLog -notmatch '# fail 0\b') { throw 'Required acceptance contains a skipped or failed test' }

    $env:WEBCODEX_TEST_AGENT_PATH = $agent
    $env:WEBCODEX_AIX_LOCAL_ONLY = '1'
    try { Invoke-Check 'local-only-exe' 'node' @('--test','ai-studio-extension/real-local.test.cjs') }
    finally { Remove-Item Env:WEBCODEX_AIX_LOCAL_ONLY }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archivePath = Join-Path $output 'webcodex-ai-studio-bridge.zip'
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    $members = @{}
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($members.ContainsKey($name) -or $name -match '(^/|\\|(^|/)\.\.(/|$))') { throw "Unsafe ZIP member $name" }
            $source = Join-Path $PSScriptRoot $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Unknown ZIP member $name" }
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
            finally { $stream.Dispose(); $sha.Dispose() }
            if ($hash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()) { throw "ZIP source mismatch $name" }
            $members[$name] = $hash
        }
        $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
        $required = @($manifest.background.service_worker, 'manifest.json', 'panel.html', 'panel.css', 'vendor/LICENSES.txt')
        foreach ($content in $manifest.content_scripts) { $required += $content.js }
        $background = Get-Content -LiteralPath (Join-Path $PSScriptRoot $manifest.background.service_worker) -Raw
        $imports = [regex]::Match($background, 'importScripts\(([^)]+)\)').Groups[1].Value
        foreach ($match in [regex]::Matches($imports, "'([^']+)'")) { $required += $match.Groups[1].Value }
        $panel = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'panel.html') -Raw
        foreach ($match in [regex]::Matches($panel, '<script src="([^"]+)"')) { $required += $match.Groups[1].Value }
        foreach ($name in $required) { if (-not $members.ContainsKey($name)) { throw "Missing ZIP dependency $name" } }
        foreach ($name in $members.Keys) { if ($name -notin $required) { throw "Unexpected ZIP member $name" } }
    } finally { $zip.Dispose() }

    $finalHashes = Get-SourceHashes
    if (($sourceHashes | ConvertTo-Json -Compress) -ne ($finalHashes | ConvertTo-Json -Compress) -or $sourceCommit -ne (& git rev-parse HEAD).Trim()) { throw 'Source changed during release verification' }
    $artifacts = [ordered]@{}
    $readme = Join-Path $output 'README.ru.md'
    Copy-Item -LiteralPath (Join-Path $root 'README.ru.md') -Destination $readme
    foreach ($path in @($agent,$archivePath,$readme)) { $artifacts[[IO.Path]::GetFileName($path)] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $report = [ordered]@{
        sourceCommit=$sourceCommit; sourceDirty=$sourceDirty; builtAtUTC=[DateTime]::UtcNow.ToString('o')
        versions=@{extension=$release.version; agent=$release.webcodexRelease.agent; gateRegression=$release.webcodexRelease.gate; replyProtocols=$release.webcodexRelease.replyProtocols}
        checks=$checks; artifacts=$artifacts; archiveMembers=$members; sourceHashes=$sourceHashes
        tools=@{go=(& go version); node=(& node --version); powershell=$PSVersionTable.PSVersion.ToString()}
        liveAcceptance='manual authenticated AI Studio check required'; publishable=$false
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Copy-Item -LiteralPath (Join-Path $scratch 'required-real-tests.log') -Destination (Join-Path $output 'acceptance-tests.txt')
    Write-Output "Verified local candidate $output source=$sourceCommit dirty=$sourceDirty"
} catch {
    if ($reportPath) { @{sourceCommit=$sourceCommit; status='incomplete'; error=$_.Exception.Message; checks=$checks; publishable=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8 }
    throw
} finally { Pop-Location }
