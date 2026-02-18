#!/bin/bash
set -e

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# Define output directory for binaries
OUTPUT_BIN_DIR="${PROJECT_ROOT}/bin"

mkdir -p "$OUTPUT_BIN_DIR"
echo "Cleaning output directory: $OUTPUT_BIN_DIR"
rm -f "$OUTPUT_BIN_DIR"/*

# Detect Conan executable
if command -v conan &> /dev/null; then
    CONAN_CMD="conan"
elif [ -f "$PROJECT_ROOT/.venv/bin/conan" ]; then
    CONAN_CMD="$PROJECT_ROOT/.venv/bin/conan"
else
    echo "ERROR: 'conan' command not found."
    echo "Checked: globally and at $PROJECT_ROOT/.venv/bin/conan"
    exit 1
fi

build_release_config() {
    local config_name="$1"
    local clickhouse="$2"
    local arena="$3"
    local logging="$4"
    local redis="$5"
    
    # Always build in Release mode for this script
    local build_type="Release"

    echo "========================================"
    echo "Building Release: $config_name"
    echo "========================================"

    # Sanitize config_name for directory use
    local safe_config_name="${config_name// /_}"
    safe_config_name="${safe_config_name//,/_}"
    safe_config_name="${safe_config_name//=/_}"
    safe_config_name="${safe_config_name//(/}"
    safe_config_name="${safe_config_name//)/}"
    
    # Create build directory in PROJECT_ROOT
    local build_dir="${PROJECT_ROOT}/cmake-build-release-${safe_config_name}"
    
    # Clean up previous build to ensure CMake uses the new toolchain
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
    fi
    mkdir -p "$build_dir"
    cd "$build_dir"

    # Install Conan dependencies for this specific build config
    echo "Running Conan install..."
    # Point to PROJECT_ROOT for conanfile.txt
    if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing -s build_type="$build_type" -c "tools.build:cflags=['-std=gnu11']" > /dev/null; then
        echo "ERROR: Conan install failed for: $config_name"
        exit 1
    fi

    # Configure CMake using the Conan toolchain
    # Point to PROJECT_ROOT for CMakeLists.txt
    if ! cmake -DUSE_CLICKHOUSE="$clickhouse" \
              -DUSE_ARENA="$arena" \
              -DENABLE_LOGGING="$logging" \
              -DUSE_REDIS="$redis" \
              -DCMAKE_BUILD_TYPE="$build_type" \
              -DCMAKE_TOOLCHAIN_FILE="build/$build_type/generators/conan_toolchain.cmake" \
              "$PROJECT_ROOT" > /dev/null; then
        echo "ERROR: CMake configuration failed for: $config_name"
        exit 1
    fi

    if ! cmake --build . -j$(nproc) > /dev/null; then
        echo "ERROR: Compilation failed for: $config_name"
        exit 1
    fi

    # Copy binary to output folder
    local output_name="cnetflow_${safe_config_name}"
    if [ -f "cnetflow" ]; then
        cp "cnetflow" "${OUTPUT_BIN_DIR}/${output_name}"
        echo "SUCCESS: Created ${OUTPUT_BIN_DIR}/${output_name}"
    else
        echo "ERROR: Binary not found for $config_name"
        exit 1
    fi
    echo ""
}

# 1. Minimal build (everything OFF)
build_release_config "Minimal" OFF OFF OFF OFF

# 2. Standard with Logging
build_release_config "Logging" OFF OFF ON ON

# 3. Arena ON
build_release_config "Arena" OFF ON OFF ON

# 4. Arena + Logging
build_release_config "Arena_Logging" OFF ON ON ON

# 5. ClickHouse
build_release_config "ClickHouse" ON OFF OFF ON

# 6. ClickHouse + Logging
build_release_config "ClickHouse_Logging" ON OFF ON ON

# 7. ClickHouse + Arena
build_release_config "ClickHouse_Arena" ON ON OFF ON

# 8. All ON (Maximum features)
build_release_config "All_ON" ON ON ON ON

# 9. Redis OFF (Hashmap fallback)
build_release_config "No_Redis" OFF ON ON OFF

echo ""
echo "###############################################"
echo "# Release builds complete. Binaries in ${OUTPUT_BIN_DIR}"
echo "###############################################"
ls -lh "${OUTPUT_BIN_DIR}"
