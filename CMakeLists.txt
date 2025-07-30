cmake_minimum_required(VERSION 3.21)

# Set policy to silence OUTPUTS + TARGET warning in custom_command
if(POLICY CMP0175)
  cmake_policy(SET CMP0175 NEW)
endif()

# Default build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Basic project info
set(VERSION_FILE Version)
file(STRINGS ${VERSION_FILE} PROJECT_VERSION)
project(tzsp2pcapng VERSION ${PROJECT_VERSION} DESCRIPTION "TZSP to PcapNG converter")

# Install paths
set(PROG_INSTALL_DIR local/bin)
set(MAN_INSTALL_DIR  local/share/man)

# Subdirectories
add_subdirectory(src/tzsp2pcapng)
add_subdirectory(man)

# Optional DEB packaging
if(CPACK_GENERATOR STREQUAL "DEB")

  set(PKG_NAME        ${PROJECT_NAME})
  set(PKG_VERSION     ${PROJECT_VERSION})
  set(PKG_MAINTAINER  "Roger Hunen <roger@hunen.net>")

  set(PKG_DEPENDS
    "libc6 (>= 2.34)"
  )
  set(PKG_SUGGESTS "")

  if(NOT PKG_ARCHITECTURE)
    # Try dpkg
    execute_process(
      COMMAND dpkg --print-architecture
      OUTPUT_VARIABLE _OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE _RESULT
    )

    if(_RESULT EQUAL 0)
      set(PKG_ARCHITECTURE ${_OUTPUT})
    else()
      # Fallback: uname
      execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE _OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _UNAME_RESULT
      )
      if(_UNAME_RESULT EQUAL 0)
        set(PKG_ARCHITECTURE ${_OUTPUT})
      else()
        set(PKG_ARCHITECTURE "unknown")
        message(WARNING "-- Could not determine architecture. Using 'unknown'")
      endif()
    endif()

    set(PKG_ARCHITECTURE ${PKG_ARCHITECTURE} CACHE STRING "Package architecture")
    message(STATUS "-- Package architecture: ${PKG_ARCHITECTURE}")
  endif()

  string(JOIN ", " _PKG_DEPENDS  ${PKG_DEPENDS})
  string(JOIN ", " _PKG_SUGGESTS ${PKG_SUGGESTS})

  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER      ${PKG_MAINTAINER})
  set(CPACK_DEBIAN_FILE_NAME               ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCHITECTURE}.deb)
  set(CPACK_DEBIAN_PACKAGE_NAME            ${PKG_NAME})
  set(CPACK_DEBIAN_PACKAGE_VERSION         ${PKG_VERSION})
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE    ${PKG_ARCHITECTURE})
  set(CPACK_DEBIAN_PACKAGE_SECTION         misc)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS         ${_PKG_DEPENDS})
  set(CPACK_DEBIAN_PACKAGE_SUGGESTS        ${_PKG_SUGGESTS})

endif()

include(CPack)
