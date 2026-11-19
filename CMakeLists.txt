cmake_minimum_required(VERSION 3.16)
project(ipwatchd C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET dbus-1 polkit-gobject-1 json-c)

find_library(PCAP_LIB NAMES pcap REQUIRED)
find_library(NET_LIB  NAMES net  REQUIRED)

set(IPWATCHD_SOURCES
    src/analyse.c
    src/config.c
    src/daemonize.c
    src/dbus.c
    src/devinfo.c
    src/genarp.c
    src/ipwatchd.c
    src/message.c
    src/securityloader.c
    src/signal.c
    src/utils.c)

add_executable(ipwatchd ${IPWATCHD_SOURCES})
target_include_directories(ipwatchd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ipwatchd PRIVATE
    ${PCAP_LIB}
    ${NET_LIB}
    PkgConfig::DEPS)
