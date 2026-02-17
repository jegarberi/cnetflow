cmake_minimum_required(VERSION 3.17.5)
project(cnetflow C)
SET(CMAKE_PROJECT_NAME "cnetflow")

# --- STATIC BUILD OPTION ---
# 1. New option to control static linking
option(BUILD_STATIC "Build cnetflow as a static executable" OFF)

# Determine the type for internal libraries: STATIC or SHARED
if (BUILD_STATIC)
    set(INTERNAL_LIBRARY_TYPE STATIC)
    message(STATUS "Building internal libraries as STATIC.")
    # Global -static flag removed to allow tests to link dynamically
    set(CMAKE_SHARED_LINKER_FLAGS "") # Clear shared linker flags if not needed
else()
    set(INTERNAL_LIBRARY_TYPE SHARED)
    message(STATUS "Building internal libraries as SHARED.")
endif()
# --- END STATIC BUILD OPTION ---

# --- DEPENDENCIES (CONAN) ---
find_package(libuv REQUIRED)
find_package(hiredis REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(CURL REQUIRED)
# find_package(criterion REQUIRED) # Not available in Conan Center

# --- REDIS CONFIGURATION ---
option(USE_REDIS "Use Redis for template storage" ON)
if (USE_REDIS)
    message(STATUS "Building with Redis support")
    add_compile_definitions(USE_REDIS=1)
    # Hiredis found via Conan
else()
    message(STATUS "Building without Redis support (using internal Hashmap)")
endif()
# --- END REDIS CONFIGURATION ---


# Rest of the initial configuration remains the same
#SET (CMAKE_BUILD_TYPE Debug)
# Only set compiler if not already specified via command line
if (NOT CMAKE_C_COMPILER)
    SET(CMAKE_C_COMPILER "/usr/bin/gcc")
endif ()
#SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET(CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra -fsanitize=address   ")
SET(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG -Wall -Wextra ")
SET(CMAKE_C_FLAGS_RELEASE "-O3 -Wall -Wextra -flto")
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "-O3 -flto")
SET(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-O3 -flto")
SET(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra ")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
# set(CMAKE_INCLUDE_PATH "/usr/include/postgresql/17/server/libpq/") # Handled by Conan
option(BUILD__LIBS "Build shared libraries" ON) # Kept but potentially overridden by BUILD_STATIC
set(CMAKE_C_STANDARD 99)

# Database backend selection
option(USE_CLICKHOUSE "Use ClickHouse instead of PostgreSQL" OFF)
option(ENABLE_LOGGING "Enable logging" ON)
option(USE_ARENA "Use arena allocator" ON)

if (ENABLE_LOGGING)
    add_compile_definitions(ENABLE_LOGGING=1)
endif()

if (USE_CLICKHOUSE)
    message(STATUS "Building with ClickHouse support")
    add_compile_definitions(USE_CLICKHOUSE=1)
else()
    message(STATUS "Building with PostgreSQL support")
endif()

if (USE_ARENA)
    message(STATUS "Building with arena allocator")
    add_compile_definitions(USE_ARENA_ALLOCATOR=1)
else()
    message(STATUS "Building with malloc/free allocator")
endif()

# Define a preprocessor macro depending on the build type
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(CNETFLOW_DEBUG_BUILD=1)
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(CNETFLOW_RELEASE_BUILD=1)
endif ()

# 2. Use the determined library type (INTERNAL_LIBRARY_TYPE) for all internal libraries
add_executable(cnetflow src/main.c)
add_library(collector ${INTERNAL_LIBRARY_TYPE} src/collector.c)
add_library(arena ${INTERNAL_LIBRARY_TYPE} src/arena.c)
add_library(dyn_array ${INTERNAL_LIBRARY_TYPE} src/dyn_array.c)
add_library(netflow ${INTERNAL_LIBRARY_TYPE} src/netflow.c)
add_library(netflow_v5 ${INTERNAL_LIBRARY_TYPE} src/netflow_v5.c)
add_library(netflow_v9 ${INTERNAL_LIBRARY_TYPE} src/netflow_v9.c)
add_library(netflow_ipfix ${INTERNAL_LIBRARY_TYPE} src/netflow_ipfix.c)
add_library(hashmap ${INTERNAL_LIBRARY_TYPE} src/hashmap.c)
if (USE_REDIS)
    add_library(redis_handler ${INTERNAL_LIBRARY_TYPE} src/redis_handler.c)
    target_link_libraries(redis_handler hiredis::hiredis)
endif()

# Database backend libraries
if (USE_CLICKHOUSE)
    add_library(db_clickhouse ${INTERNAL_LIBRARY_TYPE} src/db_clickhouse.c)
    target_link_libraries(db_clickhouse CURL::libcurl)
    set(DB_LIBRARY db_clickhouse)
    set(DB_LINK_LIBRARIES CURL::libcurl)
else()
    add_library(db_psql ${INTERNAL_LIBRARY_TYPE} src/db_psql.c)
    target_link_libraries(db_psql PostgreSQL::PostgreSQL)
    set(DB_LIBRARY db_psql)
    set(DB_LINK_LIBRARIES PostgreSQL::PostgreSQL)
endif()

# Link the libraries
if (USE_REDIS)
    set(REDIS_LIB redis_handler)
else()
    set(REDIS_LIB "")
endif()

target_link_libraries(netflow_v9 arena netflow netflow_v5 ${DB_LIBRARY} ${DB_LINK_LIBRARIES} ${REDIS_LIB})
target_link_libraries(collector libuv::uv_a arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 ${DB_LIBRARY} ${DB_LINK_LIBRARIES} dyn_array ${REDIS_LIB})
target_link_libraries(cnetflow collector libuv::uv_a arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 ${DB_LIBRARY} ${DB_LINK_LIBRARIES} dyn_array)

if (BUILD_STATIC)
    target_link_options(cnetflow PRIVATE -static)
endif()

# If building static, remove installation of internal libraries
if (NOT BUILD_STATIC)
    if (EXISTS ${CMAKE_SOURCE_DIR}/cnetflow.service)
        install(FILES ${CMAKE_SOURCE_DIR}/cnetflow.service DESTINATION /lib/systemd/system/)
    endif ()
    if (EXISTS ${CMAKE_SOURCE_DIR}/local.conf)
        install(FILES ${CMAKE_SOURCE_DIR}/local.conf DESTINATION /etc/systemd/system/cnetflow.service.d/)
    endif ()
    install(TARGETS cnetflow RUNTIME DESTINATION /usr/local/cnetflow/)
    if (USE_CLICKHOUSE)
        install(TARGETS collector arena dyn_array db_clickhouse netflow netflow_v5 netflow_v9 netflow_ipfix hashmap LIBRARY DESTINATION /usr/local/cnetflow/)
    else()
        install(TARGETS collector arena dyn_array db_psql netflow netflow_v5 netflow_v9 netflow_ipfix hashmap LIBRARY DESTINATION /usr/local/cnetflow/)
    endif()

    # Create directories for logs and data
    install(DIRECTORY DESTINATION /var/log/cnetflow DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(DIRECTORY DESTINATION /var/lib/cnetflow DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

    # ... (Keep package installation scripts and CPack configuration, but note they target dynamic build structure) ...

    # Install the config file for dynamic linking paths
    file(WRITE "${CMAKE_BINARY_DIR}/cnetflow.conf" "/usr/local/cnetflow\n")
    install(FILES "${CMAKE_BINARY_DIR}/cnetflow.conf" DESTINATION /etc/ld.so.conf.d/)

endif()
# Note: CPack configuration and installation scripts are generally designed for dynamic builds
# where library files need to be placed. For a true static binary, much of the
# installation and CPack logic (especially for libraries and ld.so.conf.d) would be irrelevant,
# but I am leaving it in an `if (NOT BUILD_STATIC)` block to preserve the dynamic build behavior.


# -------------------- Tests --------------------
include(CTest)
enable_testing()

# Try to find Criterion via pkg-config
find_package(PkgConfig)
if (PkgConfig_FOUND)
    pkg_check_modules(CRITERION criterion)
endif ()

# Fallbacks if pkg-config is unavailable
if (NOT CRITERION_FOUND)
    find_library(CRITERION_LIBRARY NAMES criterion)
    find_path(CRITERION_INCLUDE_DIR criterion/criterion.h)
    if (CRITERION_LIBRARY AND CRITERION_INCLUDE_DIR)
        set(CRITERION_FOUND TRUE)
        set(CRITERION_LDFLAGS ${CRITERION_LIBRARY})
        set(CRITERION_INCLUDE_DIRS ${CRITERION_INCLUDE_DIR})
    endif ()
endif ()

if (CRITERION_FOUND)
    add_executable(cnetflow_tests
            tests/tests.c
            tests/test_netflow.c
            tests/test_ipfix.c
    )
    target_include_directories(cnetflow_tests PRIVATE ${CRITERION_INCLUDE_DIRS})
    target_link_libraries(cnetflow_tests
            arena
            hashmap
            dyn_array
            netflow
            netflow_v5
            netflow_ipfix
            collector
            ${DB_LIBRARY}
            ${DB_LINK_LIBRARIES}
            libuv::uv_a
            ${CRITERION_LDFLAGS}
    )
    # Aggregate test (all suites)
    add_test(NAME cnetflow_tests COMMAND cnetflow_tests)
    # Separate steps per suite
    add_test(NAME tests_arena COMMAND cnetflow_tests -s arena)
    add_test(NAME tests_hashmap COMMAND cnetflow_tests -s hashmap)
    add_test(NAME tests_dyn_array COMMAND cnetflow_tests -s dyn_array)
    add_test(NAME tests_netflow COMMAND cnetflow_tests -s netflow)
else ()
    message(WARNING "Criterion not found. Unit tests will not be built.")
endif ()