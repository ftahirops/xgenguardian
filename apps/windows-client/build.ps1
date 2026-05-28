# Build a single self-contained Windows EXE.
# Output: bin/Release/net8.0-windows/win-x64/publish/XGenGuardian.exe
#
# Requires: .NET 8 SDK (https://dotnet.microsoft.com/download/dotnet/8.0)
#
# Usage from PowerShell:
#   cd apps\windows-client
#   .\build.ps1

dotnet publish -c Release -r win-x64 --self-contained true `
    /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true

$exe = Get-ChildItem -Recurse -Filter XGenGuardian.exe | Select-Object -First 1
Write-Host ""
Write-Host "✓ Built: $($exe.FullName)"
Write-Host ""
Write-Host "Test from an admin PowerShell:"
Write-Host "  $($exe.FullName)"
