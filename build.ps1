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
        [string]$ClickHouse,
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
    cmake -DUSE_CLICKHOUSE="$ClickHouse" `
          -DUSE_ARENA="$Arena" `
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
    Build-Config "Minimal (All OFF)" "OFF" "OFF" "OFF" "OFF" $BuildType

    # 2. Standard with Logging
    Build-Config "ENABLE_LOGGING=ON" "OFF" "OFF" "ON" "ON" $BuildType

    # 3. Arena ON
    Build-Config "USE_ARENA=ON" "OFF" "ON" "OFF" "ON" $BuildType

    # 4. Arena + Logging
    Build-Config "USE_ARENA=ON, ENABLE_LOGGING=ON" "OFF" "ON" "ON" "ON" $BuildType

    # 5. ClickHouse
    Build-Config "USE_CLICKHOUSE=ON" "ON" "OFF" "OFF" "ON" $BuildType

    # 6. ClickHouse + Logging
    Build-Config "USE_CLICKHOUSE=ON, ENABLE_LOGGING=ON" "ON" "OFF" "ON" "ON" $BuildType

    # 7. ClickHouse + Arena
    Build-Config "USE_CLICKHOUSE=ON, USE_ARENA=ON" "ON" "ON" "OFF" "ON" $BuildType

    # 8. All ON
    Build-Config "All ON" "ON" "ON" "ON" "ON" $BuildType

    # 9. Redis OFF
    Build-Config "USE_REDIS=OFF" "OFF" "ON" "ON" "OFF" $BuildType
}

Write-Host ""
Write-Host "###############################################"
Write-Host "# All configurations built successfully!"
Write-Host "###############################################"
