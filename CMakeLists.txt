cmake_minimum_required(VERSION 3.25)
project(cnetflow C)
SET(CMAKE_PROJECT_NAME "cnetflow")
#SET (CMAKE_BUILD_TYPE Debug)
SET(CMAKE_C_COMPILER "/usr/bin/gcc")
#SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET(CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra -pedantic ")
SET(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG -Wall -Wextra -pedantic")
SET(CMAKE_C_FLAGS_RELEASE "-O4 -Wall -Wextra -pedantic")
SET(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra -pedantic")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_INCLUDE_PATH "/usr/include/postgresql/17/server/libpq/")
option(BUILD__LIBS "Build shared libraries" ON)
set(CMAKE_C_STANDARD 99)
# Define a preprocessor macro depending on the build type
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(CNETFLOW_DEBUG_BUILD=1)
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer -g")
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer -g")
    #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    #set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(CNETFLOW_RELEASE_BUILD=1)
endif ()

add_executable(cnetflow src/main.c)
add_library(collector SHARED src/collector.c)
add_library(arena SHARED src/arena.c)
add_library(cnetflow_snmp SHARED src/cnetflow_snmp.c)
add_library(dyn_array SHARED src/dyn_array.c)
add_library(db_psql SHARED src/db_psql.c)
add_library(netflow SHARED src/netflow.c)
add_library(netflow_v5 SHARED src/netflow_v5.c)
add_library(netflow_v9 SHARED src/netflow_v9.c)
add_library(netflow_ipfix SHARED src/netflow_ipfix.c)
add_library(hashmap SHARED src/hashmap.c)
target_link_libraries(db_psql pq)
target_link_libraries(netflow_v9 arena netflow netflow_v5)
target_link_libraries(cnetflow_snmp netsnmp)
target_link_libraries(collector uv arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 db_psql pq cnetflow_snmp netsnmp dyn_array)
target_link_libraries(cnetflow collector uv arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 db_psql pq cnetflow_snmp netsnmp dyn_array)

install(FILES cnetflow.service DESTINATION /lib/systemd/system/)
install(FILES local.conf DESTINATION /etc/systemd/system/cnetflow.service.d/)
install(TARGETS cnetflow RUNTIME DESTINATION /usr/local/cnetflow/)
install(TARGETS collector arena cnetflow_snmp dyn_array db_psql netflow netflow_v5 netflow_v9 netflow_ipfix hashmap LIBRARY DESTINATION /usr/local/cnetflow/)

# Create directories for logs and data
install(DIRECTORY DESTINATION /var/log/cnetflow DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(DIRECTORY DESTINATION /var/lib/cnetflow DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

# Create package installation scripts
file(WRITE "${CMAKE_BINARY_DIR}/preinst" "#!/bin/bash
# Pre-installation script for cnetflow
set -e

# Create cnetflow group if it doesn't exist
if ! getent group cnetflow >/dev/null 2>&1; then
    groupadd --system cnetflow
fi

# Create cnetflow user if it doesn't exist
if ! getent passwd cnetflow >/dev/null 2>&1; then
    useradd --system --gid cnetflow --home-dir /var/lib/cnetflow --shell /bin/false --comment \"Cnetflow service user\" cnetflow
fi

exit 0
")

file(WRITE "${CMAKE_BINARY_DIR}/postinst" "#!/bin/bash
# Post-installation script for cnetflow
set -e

# Set ownership and permissions
chown -R cnetflow:cnetflow /usr/local/cnetflow
chown -R cnetflow:cnetflow /var/log/cnetflow
chown -R cnetflow:cnetflow /var/lib/cnetflow

# Set executable permissions
chmod 755 /usr/local/cnetflow/cnetflow
chmod 644 /usr/local/cnetflow/*.so

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable cnetflow.service

exit 0
")

file(WRITE "${CMAKE_BINARY_DIR}/prerm" "#!/bin/bash
# Pre-removal script for cnetflow
set -e

# Stop and disable service if it's running
if systemctl is-active --quiet cnetflow.service; then
    systemctl stop cnetflow.service
fi

if systemctl is-enabled --quiet cnetflow.service; then
    systemctl disable cnetflow.service
fi

exit 0
")

file(WRITE "${CMAKE_BINARY_DIR}/postrm" "#!/bin/bash
# Post-removal script for cnetflow
set -e

case \"\$1\" in
    purge)
        # Remove user and group on purge
        if getent passwd cnetflow >/dev/null 2>&1; then
            userdel cnetflow
        fi
        if getent group cnetflow >/dev/null 2>&1; then
            groupdel cnetflow
        fi
        
        # Remove data directories
        rm -rf /var/log/cnetflow
        rm -rf /var/lib/cnetflow
        ;;
    remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
        # Don't remove user/group on normal removal or upgrade
        ;;
esac

systemctl daemon-reload

exit 0
")

# CPack Configuration
set(CPACK_PACKAGE_NAME "cnetflow")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_CONTACT "jgarberi@arca.gob.ar")
set(CPACK_PACKAGE_DESCRIPTION "Cnetflow is a netflow collector and analyzer tool")
set(CPACK_PACKAGE_VENDOR "No.ORG.SA")

# Set CPack generator options
set(CPACK_GENERATOR "DEB;RPM;TGZ")

# DEB-specific settings
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Juan Garberi <jgarberi@arca.gob.ar>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpq-dev, libuv1-dev, libsnmp-dev")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

# DEB package scripts
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/preinst;${CMAKE_BINARY_DIR}/postinst;${CMAKE_BINARY_DIR}/prerm;${CMAKE_BINARY_DIR}/postrm")

# RPM-specific settings
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-or-later")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set(CPACK_RPM_PACKAGE_REQUIRES "postgresql-devel, libuv-devel, net-snmp-devel")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")

# RPM package scripts
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/preinst")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/prerm")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/postrm")

# Enable CPack packaging
include(CPack)
set_target_properties(cnetflow PROPERTIES
        INSTALL_RPATH "/usr/local/cnetflow"
        INSTALL_RPATH_USE_LINK_PATH TRUE
)
file(WRITE "${CMAKE_BINARY_DIR}/cnetflow.conf" "/usr/local/cnetflow\n")
install(FILES "${CMAKE_BINARY_DIR}/cnetflow.conf" DESTINATION /etc/ld.so.conf.d/)