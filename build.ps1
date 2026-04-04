$ErrorActionPreference = "Stop"

# Resolve project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = $ScriptDir

# Check for Conan
if (Get-Command conan -ErrorAction SilentlyContinue) {
    $ConanCmd = "conan"
} elseif (Test-Path "$ProjectRoot\.venv\Scripts\conan.exe") {
    $ConanCmd = "$ProjectRoot\.venv\Scripts\conan.exe"
} else {
    Write-Error "'conan' command not found. Please install Conan or activate your virtual environment."
    exit 1
}

function Build-Config {
    param (
        [string]$ConfigName,
        [string]$Arena,
        [string]$Logging,
        [string]$Redis,
        [string]$BuildType
    )

    Write-Host "========================================"
    Write-Host "Building: $ConfigName ($BuildType)"
    Write-Host "========================================"

    $SafeConfigName = $ConfigName -replace " ", "_" -replace ",", "_" -replace "=", "_"
    $BuildDir = Join-Path $ProjectRoot "cmake-build-$SafeConfigName-$BuildType"

    if (Test-Path $BuildDir) {
        Remove-Item -Path $BuildDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
    Set-Location $BuildDir

    Write-Host "Running Conan install..."
    & $ConanCmd install "$ProjectRoot" --output-folder=. --build=missing -s build_type=$BuildType -c "tools.build:cflags=['/std:c11']"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Conan install failed for: $ConfigName ($BuildType)"
        exit 1
    }

    Write-Host "Configuring CMake..."
    cmake -DUSE_ARENA="$Arena" `
          -DENABLE_LOGGING="$Logging" `
          -DUSE_REDIS="$Redis" `
          -DCMAKE_BUILD_TYPE="$BuildType" `
          -DCMAKE_TOOLCHAIN_FILE="$BuildDir/build/$BuildType/generators/conan_toolchain.cmake" `
          "$ProjectRoot"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configuration failed for: $ConfigName ($BuildType)"
        exit 1
    }

    Write-Host "Building..."
    cmake --build . --config $BuildType
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Compilation failed for: $ConfigName ($BuildType)"
        exit 1
    }

    Write-Host "SUCCESS: $ConfigName ($BuildType) built successfully"
    Write-Host ""
}

# Test configurations
foreach ($BuildType in "Release", "Debug") {
    Write-Host ""
    Write-Host "###############################################"
    Write-Host "# Testing $BuildType builds"
    Write-Host "###############################################"
    Write-Host ""

    # 1. Minimal build
    Build-Config "Minimal" "OFF" "OFF" "OFF" $BuildType

    # 2. Standard with Logging
    Build-Config "Logging" "OFF" "ON" "ON" $BuildType

    # 3. Arena ON
    Build-Config "Arena" "ON" "OFF" "ON" $BuildType

    # 4. Arena + Logging
    Build-Config "Arena_Logging" "ON" "ON" "ON" $BuildType

    # 5. Redis OFF
    Build-Config "No_Redis" "ON" "ON" "OFF" $BuildType
}

Write-Host ""
Write-Host "###############################################"
Write-Host "# All configurations built successfully!"
Write-Host "###############################################"
