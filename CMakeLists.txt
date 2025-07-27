cmake_minimum_required(VERSION 3.21)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

set(BUILD_DIR    ${CMAKE_CURRENT_BINARY_DIR})
set(PROJECT_DIR  ${CMAKE_CURRENT_SOURCE_DIR})
set(VERSION_FILE Version)

file(STRINGS ${VERSION_FILE} PROJECT_VERSION)
project("tzsp2pcapng" VERSION ${PROJECT_VERSION} DESCRIPTION "TZSP to PcapNG converter")

set(PROG_INSTALL_DIR local/bin)
set(MAN_INSTALL_DIR  local/share/man)

add_subdirectory(src/tzsp2pcapng)
add_subdirectory(man)

###########
# Package #
###########

set(PKG_NAME        ${PROJECT_NAME})
set(PKG_VERSION     ${PROJECT_VERSION})
set(PKG_MAINTAINER  "Roger Hunen <roger@hunen.net>")

set(PKG_DEPENDS
  "libc6 (>= 2.34)"
)
set(PKG_SUGGESTS
)

if (NOT PKG_ARCHITECTURE)
  execute_process(
    COMMAND dpkg --print-architecture
    OUTPUT_VARIABLE _OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _RESULT
  )
  if (_RESULT)
    message(FATAL_ERROR "-- Unable to determine package architecture: ${_RESULT}")
  endif ()

  set(PKG_ARCHITECTURE ${_OUTPUT} CACHE STRING "Package architecture")
  message("-- Package architecture: ${PKG_ARCHITECTURE}")
endif ()

set(CPACK_GENERATOR "DEB")
set(CPACK_DEB_COMPONENT_INSTALL ON)

set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER      ${PKG_MAINTAINER})

# Main package

string(JOIN ", " _PKG_DEPENDS  ${PKG_DEPENDS})
string(JOIN ", " _PKG_SUGGESTS ${PKG_SUGGESTS})

set(CPACK_DEBIAN_FILE_NAME            ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCHITECTURE}.deb)
set(CPACK_DEBIAN_PACKAGE_NAME         ${PKG_NAME})
set(CPACK_DEBIAN_PACKAGE_VERSION      ${PKG_VERSION})
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${PKG_ARCHITECTURE})
set(CPACK_DEBIAN_PACKAGE_SECTION      misc)
set(CPACK_DEBIAN_PACKAGE_DEPENDS      ${_PKG_DEPENDS})
set(CPACK_DEBIAN_PACKAGE_SUGGESTS     ${_PKG_SUGGESTS})

include(CPack)
