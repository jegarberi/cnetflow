# Build Instructions for cnetflow

This document provides detailed instructions for building, testing, and installing `cnetflow`.

## Prerequisites

*   **CMake**: Version 3.17.5 or higher.
*   **C Compiler**: GCC or Clang (supporting C99).
*   **Conan**: (Optional, recommended) Package manager for C/C++.
*   **Make** or **Ninja**: Build tool.

## Build Methods

You can build `cnetflow` using Conan for automatic dependency management (recommended for development) or using system-installed packages.

### Option 1: Building with Conan (Recommended)

This method automatically fetches and builds specific versions of dependencies as defined in `conanfile.txt`.

1.  **Install Conan** (if not already installed):
    ```bash
    pip install conan
    ```

2.  **Install Dependencies**:
    From the project root, run:
    ```bash
    conan install . --output-folder=build --build=missing
    ```

3.  **Configure CMake**:
    ```bash
    cd build
    cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
    ```

4.  **Build**:
    ```bash
    cmake --build .
    ```

### Option 2: Building with System Packages

If you prefer to use libraries installed via your OS package manager (e.g., `apt`, `yum`, or `brew`), ensure you have development headers installed for:
*   `libuv`
*   `hiredis`
*   `libpq` (PostgreSQL)
*   `libcurl`
*   `criterion` (optional, for tests)

**Example (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install cmake build-essential libuv1-dev libhiredis-dev libpq-dev libcurl4-openssl-dev
```

**Build Steps:**
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Build Options

You can customize the build by passing `-D<OPTION>=<ON|OFF>` to the `cmake` command.

| Option | Default | Description |
| :--- | :--- | :--- |
| `BUILD_STATIC` | `OFF` | Build `cnetflow` as a static executable. |
| `USE_REDIS` | `ON` | Enable Redis support for template storage. |
| `USE_CLICKHOUSE` | `OFF` | Use ClickHouse backend instead of PostgreSQL. |
| `ENABLE_LOGGING` | `ON` | Enable application logging. |
| `USE_ARENA` | `ON` | Use custom arena allocator (performance optimization). |

**Example:**
To build without Redis and with logging disabled:
```bash
cmake .. -DUSE_REDIS=OFF -DENABLE_LOGGING=OFF
```

## Running Tests

Unit tests are built if `criterion` is found.

Run all tests using CTest:
```bash
cd build
ctest
```

Or run specific test suites directly:
```bash
./cnetflow_tests
```
(Arguments: `-s <suite_name>` to run a specific suite, e.g., `-s arena`)

## Installation

To install the binary and service files to the system:

```bash
sudo cmake --install .
```
Or with Make:
```bash
sudo make install
```

## Docker Build

To build the Docker image (which uses the system package approach):

```bash
docker build -t cnetflow .
```
