#!/bin/bash
set -e
# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

mkdir -p build
cd build

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

build_config() {
    local config_name="$1"
    local clickhouse="$2"
    local arena="$3"
    local logging="$4"
    local redis="$5"
    local build_type="$6"

    echo "========================================"
    echo "Building: $config_name ($build_type)"
    echo "========================================"

    # Sanitize config_name for directory use
    local safe_config_name="${config_name// /_}"
    safe_config_name="${safe_config_name//,/_}"
    safe_config_name="${safe_config_name//=/_}"
    
    # Create build directory in PROJECT_ROOT
    local build_dir="${PROJECT_ROOT}/cmake-build-${safe_config_name}-${build_type}"
    
    # Clean up previous build to ensure CMake uses the new toolchain
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
    fi
    mkdir -p "$build_dir"
    cd "$build_dir"

    # Install Conan dependencies for this specific build config
    echo "Running Conan install..."
    # Point to PROJECT_ROOT for conanfile.txt
    if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing -s build_type="$build_type" -c "tools.build:cflags=['-std=gnu11']"; then
        echo "ERROR: Conan install failed for: $config_name ($build_type)"
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
              "$PROJECT_ROOT"; then
        echo "ERROR: CMake configuration failed for: $config_name ($build_type)"
        exit 1
    fi

    if ! cmake --build . -j$(nproc); then
        echo "ERROR: Compilation failed for: $config_name ($build_type)"
        exit 1
    fi

    echo "SUCCESS: $config_name ($build_type) built successfully"
    echo ""
}

# Test all configurations in both Release and Debug modes
for build_type in Release Debug; do
    echo ""
    echo "###############################################"
    echo "# Testing $build_type builds"
    echo "###############################################"
    echo ""

    # Combination 1: All OFF (except Redis default ON for now, wait, "All OFF" implies everything optional off. Let's make All OFF have Redis OFF too?)
    # No, let's keep previous behavior mostly, but "All OFF" usually means minimal features.
    # Let's add Redis arg to all calls.

    # 1. Minimal build (everything OFF)
    build_config "Minimal (All OFF)" OFF OFF OFF OFF $build_type

    # 2. Standard with Logging
    build_config "ENABLE_LOGGING=ON" OFF OFF ON ON $build_type

    # 3. Arena ON
    build_config "USE_ARENA=ON" OFF ON OFF ON $build_type

    # 4. Arena + Logging
    build_config "USE_ARENA=ON, ENABLE_LOGGING=ON" OFF ON ON ON $build_type

    # 5. ClickHouse
    build_config "USE_CLICKHOUSE=ON" ON OFF OFF ON $build_type

    # 6. ClickHouse + Logging
    build_config "USE_CLICKHOUSE=ON, ENABLE_LOGGING=ON" ON OFF ON ON $build_type

    # 7. ClickHouse + Arena
    build_config "USE_CLICKHOUSE=ON, USE_ARENA=ON" ON ON OFF ON $build_type

    # 8. All ON (Maximum features)
    build_config "All ON" ON ON ON ON $build_type

    # 9. Redis OFF (Hashmap fallback)
    build_config "USE_REDIS=OFF" OFF ON ON OFF $build_type
done

echo ""
echo "###############################################"
echo "# All configurations built successfully!"
echo "###############################################"
