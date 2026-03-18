#!/bin/bash
set -e

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# Define output directory for binaries
OUTPUT_BIN_DIR="${PROJECT_ROOT}/bin"

mkdir -p "$OUTPUT_BIN_DIR"
echo "Cleaning output directory: $OUTPUT_BIN_DIR"
find "$OUTPUT_BIN_DIR" -maxdepth 1 -type f -delete

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
    local static_build="$6"
    local build_type="$7"
    
    local static_suffix=""
    local cmake_static_flag="OFF"
    local conan_shared_option=""
    local debug_suffix=""

    if [ "$static_build" == "ON" ]; then
        static_suffix="_static"
        cmake_static_flag="ON"
        conan_shared_option="-o *:shared=False"
    fi

    if [ "$build_type" == "Debug" ]; then
        debug_suffix="_debug"
    fi

    echo "========================================"
    echo "Building ${lengthy_build_type:-$build_type} $([ "$static_build" == "ON" ] && echo "STATIC" || echo "DYNAMIC"): $config_name"
    echo "========================================"

    # Sanitize config_name for directory use
    local safe_config_name="${config_name// /_}"
    safe_config_name="${safe_config_name//,/_}"
    safe_config_name="${safe_config_name//=/_}"
    safe_config_name="${safe_config_name//(/}"
    safe_config_name="${safe_config_name//)/}"
    
    # Create build directory in PROJECT_ROOT
    # Create build directory in PROJECT_ROOT
    local build_dir="${PROJECT_ROOT}/cmake-build-${build_type,,}-${safe_config_name}${static_suffix}"
    
    # Clean up previous build to ensure CMake uses the new toolchain and options
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
    fi
    mkdir -p "$build_dir"
    cd "$build_dir"

    # Install Conan dependencies for this specific build config
    echo "Running Conan install..."
    # Point to PROJECT_ROOT for conanfile.txt
    # shellcheck disable=SC2086
    if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing -s build_type="$build_type" -c "tools.build:cflags=['-std=gnu11']" $conan_shared_option > /dev/null; then
        echo "ERROR: Conan install failed for: $config_name (Static: $static_build, Type: $build_type)"
        exit 1
    fi

    # Configure CMake using the Conan toolchain
    # Point to PROJECT_ROOT for CMakeLists.txt
    if ! cmake -DUSE_CLICKHOUSE="$clickhouse" \
              -DUSE_ARENA="$arena" \
              -DENABLE_LOGGING="$logging" \
              -DUSE_REDIS="$redis" \
              -DBUILD_STATIC="$cmake_static_flag" \
              -DCMAKE_BUILD_TYPE="$build_type" \
              -DCMAKE_TOOLCHAIN_FILE="build/$build_type/generators/conan_toolchain.cmake" \
              "$PROJECT_ROOT" > /dev/null; then
        echo "ERROR: CMake configuration failed for: $config_name (Static: $static_build, Type: $build_type)"
        exit 1
    fi

    if ! cmake --build . -j$(nproc) > /dev/null; then
        echo "ERROR: Compilation failed for: $config_name (Static: $static_build, Type: $build_type)"
        exit 1
    fi

    # Copy binary to output folder
    local output_name="cnetflow_${safe_config_name}${static_suffix}${debug_suffix}"
    if [ -f "cnetflow" ]; then
        cp "cnetflow" "${OUTPUT_BIN_DIR}/${output_name}"
        echo "SUCCESS: Created ${OUTPUT_BIN_DIR}/${output_name}"
    else
        echo "ERROR: Binary not found for $config_name (Static: $static_build, Type: $build_type)"
        exit 1
    fi
    echo ""
}

run_builds() {
    local name="$1"
    local ch="$2"
    local ar="$3"
    local log="$4"
    local rd="$5"
    
    # Release
    build_config "$name" "$ch" "$ar" "$log" "$rd" "OFF" "Release"
    build_config "$name" "$ch" "$ar" "$log" "$rd" "ON" "Release"

    # Debug
    build_config "$name" "$ch" "$ar" "$log" "$rd" "OFF" "Debug"
    build_config "$name" "$ch" "$ar" "$log" "$rd" "ON" "Debug"
}

# 1. Minimal build (everything OFF)
run_builds "Minimal" OFF OFF OFF OFF

# 2. Standard with Logging
run_builds "Logging" OFF OFF ON ON

# 3. Arena ON
run_builds "Arena" OFF ON OFF ON

# 4. Arena + Logging
run_builds "Arena_Logging" OFF ON ON ON

# 5. ClickHouse
run_builds "ClickHouse" ON OFF OFF ON

# 6. ClickHouse + Logging
run_builds "ClickHouse_Logging" ON OFF ON ON

# 7. ClickHouse + Arena
run_builds "ClickHouse_Arena" ON ON OFF ON

# 8. All ON (Maximum features)
run_builds "All_ON" ON ON ON ON

# 9. Redis OFF (Hashmap fallback)
run_builds "No_Redis" OFF ON ON OFF

# 10. ClickHouse Minimal (No Arena, No Redis, No Logging)
run_builds "ClickHouse_Minimal" ON OFF OFF OFF

echo ""
echo "###############################################"
echo "# Release builds complete. Binaries in ${OUTPUT_BIN_DIR}"
echo "###############################################"
ls -lh "${OUTPUT_BIN_DIR}"
