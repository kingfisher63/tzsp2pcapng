cmake_minimum_required(VERSION 3.25)

if(POLICY CMP0175)
  cmake_policy(SET CMP0175 NEW)
endif()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

set(BUILD_DIR    ${CMAKE_CURRENT_BINARY_DIR})
set(PROJECT_DIR  ${CMAKE_CURRENT_SOURCE_DIR})
set(VERSION_FILE Version)

file(STRINGS ${VERSION_FILE} PROJECT_VERSION)
project("tzsp2pcapng" VERSION ${PROJECT_VERSION} DESCRIPTION "TZSP to PcapNG converter")

set(EXE_INSTALL_DIR  "bin")
set(MAN_INSTALL_DIR  "share/man")

add_subdirectory(src/tzsp2pcapng)
add_subdirectory(man)

set(PKG_NAME        ${PROJECT_NAME})
set(PKG_VERSION     ${PROJECT_VERSION})
set(PKG_MAINTAINER  "Roger Hunen <roger@hunen.net>")

set(PKG_DEPEND_LIBC6 "libc6" "2.34")

set(PKG_MAIN_DEPENDS
  PKG_DEPEND_LIBC6
)

include(CPack.cmake)

