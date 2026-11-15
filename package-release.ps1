$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $target = @(& go env GOOS GOARCH)
    if ($LASTEXITCODE -ne 0 -or $target[0] -ne 'windows' -or $target[1] -ne 'amd64') { throw 'This release requires the Windows amd64 Go target' }
    & ./build.ps1
    $release = Get-Content ai-studio-extension/package.json -Raw | ConvertFrom-Json
    $output = Join-Path $PSScriptRoot 'bin/aix'
    $archivePath = Join-Path $output ("AIX-" + $release.version + "-windows-x64.zip")
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $extension = [IO.Compression.ZipFile]::OpenRead((Join-Path $output 'webcodex-ai-studio-bridge.zip'))
    $archiveStream = [IO.File]::Open($archivePath, [IO.FileMode]::Create)
    $archive = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in @('webcodex-agent.exe', 'start-agent.bat')) {
            $source = if ($name -eq 'start-agent.bat') { Join-Path $PSScriptRoot $name } else { Join-Path $output $name }
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $source, $name) | Out-Null
        }
        foreach ($sourceEntry in $extension.Entries) {
            $entry = $archive.CreateEntry('ai-studio-extension/' + $sourceEntry.FullName)
            $inputStream = $sourceEntry.Open()
            $entryStream = $entry.Open()
            try { $inputStream.CopyTo($entryStream) }
            finally { $entryStream.Dispose(); $inputStream.Dispose() }
        }
    } finally {
        $archive.Dispose()
        $archiveStream.Dispose()
        $extension.Dispose()
    }
    Write-Output "Ready release ZIP: $archivePath"
} finally { Pop-Location }
