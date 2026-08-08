#!/bin/bash

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
    return 1
fi

if ! command -v zig &> /dev/null; then
    echo "ERROR: 'zig' command not found. It is required for musl static builds."
    return 1
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
    local metrics="$5"
    local mmsg="$6"
    local mmsg_size="$7"
    local max_unp_size="$8"
    local static_build="$9"
    local build_type="${10}"
    
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
            return 1
        fi
    else
        if ! "$CONAN_CMD" install "$PROJECT_ROOT" --output-folder=. --build=missing -s build_type="$build_type" -c "tools.build:cflags=['-std=gnu11']"; then
            echo "ERROR: Conan install failed for: $config_name ($build_type)"
            return 1
        fi
    fi

    # Configure CMake using the Conan toolchain
    # Point to PROJECT_ROOT for CMakeLists.txt
    if ! cmake -DUSE_ARENA="$arena" \
              -DENABLE_LOGGING="$logging" \
              -DUSE_REDIS="$redis" \
              -DENABLE_METRICS="$metrics" \
              -DENABLE_MMSG="$mmsg" \
              -DMMSG_BATCH_SIZE="$mmsg_size" \
              -DMAX_UNPARSED_FLOWS="$max_unp_size" \
              -DBUILD_STATIC="$cmake_static_flag" \
              -DCMAKE_BUILD_TYPE="$build_type" \
              -DCMAKE_TOOLCHAIN_FILE="build/$build_type/generators/conan_toolchain.cmake" \
              "$PROJECT_ROOT"; then
        echo "ERROR: CMake configuration failed for: $config_name ($build_type)"
        return 1
    fi

    if ! cmake --build . -j$(nproc); then
        echo "ERROR: Compilation failed for: $config_name ($build_type)"
        return 1
    fi

    echo "SUCCESS: $config_name ($build_type) built successfully"
    echo ""
}

run_builds() {
    local name="$1"
    local ar="$2"
    local log="$3"
    local rd="$4"
    local met="$5"
    local msg="${6:-ON}"
    local msg_size="${7:-40}"
    local max_unp_size="${8:-1000}"
    
    build_config "$name" "$ar" "$log" "$rd" "$met" "$msg" "$msg_size" "$max_unp_size" "OFF" "Release"
    build_config "$name" "$ar" "$log" "$rd" "$met" "$msg" "$msg_size" "$max_unp_size" "ON" "Release"
    build_config "$name" "$ar" "$log" "$rd" "$met" "$msg" "$msg_size" "$max_unp_size" "OFF" "Debug"
    build_config "$name" "$ar" "$log" "$rd" "$met" "$msg" "$msg_size" "$max_unp_size" "ON" "Debug"
}

if [ -t 0 ]; then
    read -p "Do you want to build ALL 16 combinations? (y/N): " build_all
else
    build_all="y"
fi

if [[ "$build_all" =~ ^[Yy]$ ]]; then
    echo ""
    echo "###############################################"
    echo "# Testing all builds (Release/Debug, Dynamic/Static)"
    echo "###############################################"
    echo ""

    # 1. No features enabled (Minimal base)
    run_builds "None" OFF OFF OFF OFF

    # 2. Only Metrics
    run_builds "Metrics" OFF OFF OFF ON

    # 3. Only Redis
    run_builds "Redis" OFF OFF ON OFF

    # 4. Redis + Metrics
    run_builds "Redis_Metrics" OFF OFF ON ON

    # 5. Only Logging
    run_builds "Logging" OFF ON OFF OFF

    # 6. Logging + Metrics
    run_builds "Logging_Metrics" OFF ON OFF ON

    # 7. Logging + Redis
    run_builds "Logging_Redis" OFF ON ON OFF

    # 8. Logging + Redis + Metrics
    run_builds "Logging_Redis_Metrics" OFF ON ON ON

    # 9. Only Arena
    run_builds "Arena" ON OFF OFF OFF

    # 10. Arena + Metrics
    run_builds "Arena_Metrics" ON OFF OFF ON

    # 11. Arena + Redis
    run_builds "Arena_Redis" ON OFF ON OFF

    # 12. Arena + Redis + Metrics
    run_builds "Arena_Redis_Metrics" ON OFF ON ON

    # 13. Arena + Logging
    run_builds "Arena_Logging" ON ON OFF OFF

    # 14. Arena + Logging + Metrics
    run_builds "Arena_Logging_Metrics" ON ON OFF ON

    # 15. Arena + Logging + Redis
    run_builds "Arena_Logging_Redis" ON ON ON OFF

    # 16. All features enabled
    run_builds "Arena_Logging_Redis_Metrics" ON ON ON ON
else
    CONFIG_FILE="${PROJECT_ROOT}/.build_config"
    DEF_AR="Y"; DEF_LOG="Y"; DEF_RD="Y"; DEF_MET="Y"; DEF_MSG="Y"; DEF_MSG_SIZE="40"; DEF_MAX_UNP_SIZE="1000"
    DEF_MODE="B"; DEF_TYPE="B"
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi

    echo "Select features to enable (press Enter to use defaults):"
    read -p "Enable Arena Allocator? [$DEF_AR/n]: " opt_arena
    opt_arena=${opt_arena:-$DEF_AR}
    read -p "Enable Logging? [$DEF_LOG/n]: " opt_logging
    opt_logging=${opt_logging:-$DEF_LOG}
    read -p "Enable Redis? [$DEF_RD/n]: " opt_redis
    opt_redis=${opt_redis:-$DEF_RD}
    read -p "Enable Metrics? [$DEF_MET/n]: " opt_metrics
    opt_metrics=${opt_metrics:-$DEF_MET}
    read -p "Enable MMSG? [$DEF_MSG/n]: " opt_mmsg
    opt_mmsg=${opt_mmsg:-$DEF_MSG}

    ar="ON"; DEF_AR="Y"; if [[ "$opt_arena" =~ ^[Nn]$ ]]; then ar="OFF"; DEF_AR="n"; fi
    log="ON"; DEF_LOG="Y"; if [[ "$opt_logging" =~ ^[Nn]$ ]]; then log="OFF"; DEF_LOG="n"; fi
    rd="ON"; DEF_RD="Y"; if [[ "$opt_redis" =~ ^[Nn]$ ]]; then rd="OFF"; DEF_RD="n"; fi
    met="ON"; DEF_MET="Y"; if [[ "$opt_metrics" =~ ^[Nn]$ ]]; then met="OFF"; DEF_MET="n"; fi
    msg="ON"; DEF_MSG="Y"; if [[ "$opt_mmsg" =~ ^[Nn]$ ]]; then msg="OFF"; DEF_MSG="n"; fi

    msg_size="$DEF_MSG_SIZE"
    if [ "$msg" == "ON" ]; then
        read -p "MMSG Batch Size (default $DEF_MSG_SIZE): " opt_mmsg_size
        opt_mmsg_size=${opt_mmsg_size:-$DEF_MSG_SIZE}
        if [[ "$opt_mmsg_size" =~ ^[0-9]+$ ]]; then msg_size="$opt_mmsg_size"; fi
    fi
    DEF_MSG_SIZE="$msg_size"

    max_unp_size="$DEF_MAX_UNP_SIZE"
    read -p "Max Unparsed Flows Cache Size (default $DEF_MAX_UNP_SIZE): " opt_max_unp_size
    opt_max_unp_size=${opt_max_unp_size:-$DEF_MAX_UNP_SIZE}
    if [[ "$opt_max_unp_size" =~ ^[0-9]+$ ]]; then max_unp_size="$opt_max_unp_size"; fi
    DEF_MAX_UNP_SIZE="$max_unp_size"

    name="Custom"
    if [ "$ar" == "ON" ]; then name="${name}_Arena"; fi
    if [ "$log" == "ON" ]; then name="${name}_Logging"; fi
    if [ "$rd" == "ON" ]; then name="${name}_Redis"; fi
    if [ "$met" == "ON" ]; then name="${name}_Metrics"; fi
    if [ "$msg" == "ON" ]; then name="${name}_MMSG"; fi
    if [ "$name" == "Custom" ]; then name="None"; fi

    echo "Select Build Configurations (press Enter to use defaults):"
    read -p "Build Mode? [S]tatic / [D]ynamic / [B]oth [$DEF_MODE]: " opt_mode
    opt_mode=${opt_mode:-$DEF_MODE}
    read -p "Build Type? [R]elease / [D]ebug / [B]oth [$DEF_TYPE]: " opt_type
    opt_type=${opt_type:-$DEF_TYPE}

    build_static_flags=()
    DEF_MODE="B"
    if [[ "$opt_mode" =~ ^[Ss]$ ]]; then
        build_static_flags=("ON")
        DEF_MODE="S"
    elif [[ "$opt_mode" =~ ^[Dd]$ ]]; then
        build_static_flags=("OFF")
        DEF_MODE="D"
    else
        build_static_flags=("OFF" "ON")
    fi

    build_type_flags=()
    DEF_TYPE="B"
    if [[ "$opt_type" =~ ^[Rr]$ ]]; then
        build_type_flags=("Release")
        DEF_TYPE="R"
    elif [[ "$opt_type" =~ ^[Dd]$ ]]; then
        build_type_flags=("Debug")
        DEF_TYPE="D"
    else
        build_type_flags=("Release" "Debug")
    fi

    cat > "$CONFIG_FILE" <<EOF
DEF_AR="$DEF_AR"
DEF_LOG="$DEF_LOG"
DEF_RD="$DEF_RD"
DEF_MET="$DEF_MET"
DEF_MSG="$DEF_MSG"
DEF_MSG_SIZE="$DEF_MSG_SIZE"
DEF_MAX_UNP_SIZE="$DEF_MAX_UNP_SIZE"
DEF_MODE="$DEF_MODE"
DEF_TYPE="$DEF_TYPE"
EOF

    echo ""
    echo "###############################################"
    echo "# Building Custom Configuration: $name"
    echo "###############################################"
    echo ""
    for btype in "${build_type_flags[@]}"; do
        for bmode in "${build_static_flags[@]}"; do
            build_config "$name" "$ar" "$log" "$rd" "$met" "$msg" "$msg_size" "$max_unp_size" "$bmode" "$btype"
        done
    done
fi

rm -f "$CONAN_PROFILE_MUSL"

echo ""
echo "###############################################"
echo "# Build script completed successfully!"
echo "###############################################"
