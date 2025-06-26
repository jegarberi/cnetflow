cmake_minimum_required(VERSION 3.25)
project(cnetflow C)
#SET (CMAKE_BUILD_TYPE Debug)
SET(CMAKE_C_COMPILER "/usr/bin/gcc")
#SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET(CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra -pedantic ")
#SET(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG -Wall -Wextra -pedantic")
SET(CMAKE_C_FLAGS_RELEASE "-O4 -Wall -Wextra -pedantic")
#SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra -pedantic")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_INCLUDE_PATH "/usr/include/postgresql/15/server/libpq/")
option(BUILD__LIBS "Build shared libraries" ON)
set(CMAKE_C_STANDARD 99)
install(FILES cnetflow.service DESTINATION /lib/systemd/system/)
install(FILES local.conf DESTINATION /etc/systemd/system/cnetflow.service.d/)
#install(TARGETS RUNTIME DESTINATION /usr/local/cnetflow/ PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
install(TARGETS RUNTIME DESTINATION /usr/local/cnetflow/)
install(TARGETS LIBRARY DESTINATION /usr/local/cnetflow/)

#install(FILES *.so DESTINATION /usr/local/cnetflow/)
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

target_link_libraries(netflow_v9 arena)

target_link_libraries(cnetflow_snmp netsnmp)
target_link_libraries(collector uv arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 db_psql pq cnetflow_snmp netsnmp dyn_array)
target_link_libraries(cnetflow collector uv arena hashmap netflow netflow_ipfix netflow_v5 netflow_v9 db_psql pq cnetflow_snmp netsnmp dyn_array)



# Enable CPack packaging at the end of your CMakeLists.txt file
include(InstallRequiredSystemLibraries)
include(CPack)

# CPack Configuration

# Set package version and name
set(CPACK_OUTPUT_FILE_PREFIX "/usr/local/cnetflow/")
set(CPACK_PACKAGE_NAME "cnetflow")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_CONTACT "your_email@example.com")

# Set package description
set(CPACK_PACKAGE_DESCRIPTION "Cnetflow is a netflow collector and analyzer tool")

# Set package license
set(CPACK_PACKAGE_LICENSE "GPL-3.0-or-later")

# Set package vendor
set(CPACK_PACKAGE_VENDOR "Your Organization")

# Set the installation directory for the package (defaults to /usr/local)
set(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr/local/cnetflow")

# Set CPack generator options
set(CPACK_GENERATOR "DEB;RPM;TGZ")

# Set DEB-specific settings (for DEB packaging)
set(CPACK_DEB_PACKAGE_MAINTAINER "Juan Garberi <jgarberi@arca.gob.ar>")
set(CPACK_DEB_PACKAGE_DEPENDS "libpq-dev, libuv1-dev, libsnmp-dev")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Juan Garberi <jgarberi@arca.gob.ar>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpq-dev, libuv1-dev, libsnmp-dev")
# Set RPM-specific settings (for RPM packaging)
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-or-later")
set(CPACK_RPM_PACKAGE_GROUP "Tools")
set(CPACK_RPM_PACKAGE_REQUIRES "libpq-devel, libuv-devel, net-snmp-devel")

# Set TGZ-specific settings (for TGZ packaging)
set(CPACK_TGZ_PACKAGE_HOMEPAGE "https://github.com/jegarberi/cnetflow")
set(CPACK_TGZ_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Set the package architecture (optional, defaults to "x86_64")
set(CPACK_DEB_PACKAGE_ARCHITECTURE "amd64")

# If you want to include additional files in the package
# set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
# set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

