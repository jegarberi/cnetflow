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

if ! command -v zig &> /dev/null; then
    echo "ERROR: 'zig' command not found. It is required for musl static builds."
    exit 1
fi

CONAN_PROFILE_MUSL="${PROJECT_ROOT}/musl_profile"
echo "Generating Conan profile for Musl (Static)..."
CLANG_VER=$(clang --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' || echo "10")
cat > "$CONAN_PROFILE_MUSL" <<EOF
[settings]
os=Linux
arch=x86_64
compiler=clang
compiler.version=${CLANG_VER}
compiler.libcxx=libstdc++11

[conf]
tools.build:compiler_executables={"c": "${PROJECT_ROOT}/scripts/zig-cc", "cpp": "${PROJECT_ROOT}/scripts/zig-cxx"}
tools.build:cflags=["-target", "x86_64-linux-musl"]
tools.build:cxxflags=["-target", "x86_64-linux-musl"]
tools.build:exelinkflags=["-target", "x86_64-linux-musl"]
EOF

build_config() {
    local config_name="$1"
    local arena="$2"
    local logging="$3"
    local redis="$4"
    local static_build="$5"
    local build_type="$6"
    
    local static_suffix=""
    local cmake_static_flag="OFF"
    local conan_shared_option=""

    if [ "$static_build" == "ON" ]; then
        static_suffix="_static"
        cmake_static_flag="ON"
        conan_shared_option="-o *:shared=False"
    fi

    echo "========================================"
    echo "Building: $config_name ($build_type) $([ "$static_build" == "ON" ] && echo "STATIC" || echo "DYNAMIC")"
    echo "========================================"

    # Sanitize config_name for directory use
    local safe_config_name="${config_name// /_}"
    safe_config_name="${safe_config_name//,/_}"
    safe_config_name="${safe_config_name//=/_}"
    
    # Create build directory in PROJECT_ROOT
    local build_dir="${PROJECT_ROOT}/cmake-build-${safe_config_name}-${build_type}${static_suffix}"
    
    # Clean up previous build to ensure CMake uses the new toolchain
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
    fi
    mkdir -p "$build_dir"
    cd "$build_dir"

    # Install Conan dependencies for this specific build config
    echo "Running Conan install..."
    # Point to PROJECT_ROOT for conanfile.txt
    if [ "$static_build" == "ON" ]; then
        if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing \
            -pr:h "$CONAN_PROFILE_MUSL" -pr:b default \
            -s build_type="$build_type" \
            -c "tools.build:cflags=['-std=gnu11', '-target', 'x86_64-linux-musl']" \
            $conan_shared_option; then
            echo "ERROR: Conan install failed for: $config_name ($build_type)"
            exit 1
        fi
    else
        if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing -s build_type="$build_type" -c "tools.build:cflags=['-std=gnu11']"; then
            echo "ERROR: Conan install failed for: $config_name ($build_type)"
            exit 1
        fi
    fi

    # Configure CMake using the Conan toolchain
    # Point to PROJECT_ROOT for CMakeLists.txt
    if ! cmake -DUSE_ARENA="$arena" \
              -DENABLE_LOGGING="$logging" \
              -DUSE_REDIS="$redis" \
              -DBUILD_STATIC="$cmake_static_flag" \
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

run_builds() {
    local name="$1"
    local ar="$2"
    local log="$3"
    local rd="$4"
    
    build_config "$name" "$ar" "$log" "$rd" "OFF" "Release"
    build_config "$name" "$ar" "$log" "$rd" "ON" "Release"
    build_config "$name" "$ar" "$log" "$rd" "OFF" "Debug"
    build_config "$name" "$ar" "$log" "$rd" "ON" "Debug"
}

echo ""
echo "###############################################"
echo "# Testing all builds (Release/Debug, Dynamic/Static)"
echo "###############################################"
echo ""

# 1. Minimal build (everything OFF except Redis)
run_builds "Minimal" OFF OFF ON

# 2. Standard with Logging
run_builds "Logging" OFF ON ON

# 3. Arena ON
run_builds "Arena" ON OFF ON

# 4. Arena + Logging
run_builds "Arena_Logging" ON ON ON

# 5. Redis OFF (Hashmap fallback)
run_builds "No_Redis" ON ON OFF

rm -f "$CONAN_PROFILE_MUSL"

echo ""
echo "###############################################"
echo "# All configurations built successfully!"
echo "###############################################"
