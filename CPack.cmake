if (NOT FALLBACK_CPACK_GENERATOR)
  set(FALLBACK_CPACK_GENERATOR "TGZ")
endif()

#
# DEB generator
#

if (NOT DEBIAN_ARCHITECTURE)
  execute_process(
    COMMAND          dpkg --print-architecture
    RESULT_VARIABLE  _RESULT
    OUTPUT_VARIABLE  _OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  if (NOT _RESULT)
    set(DEFAULT_CPACK_GENERATOR "DEB"      CACHE STRING "Default CPack generator")
    set(DEBIAN_ARCHITECTURE     ${_OUTPUT} CACHE STRING "Debian package architecture")
  else()
    set(DEBIAN_ARCHITECTURE     "i386"     CACHE STRING "Debian package architecture")
  endif()

  if ("${DEFAULT_CPACK_GENERATOR}" STREQUAL "DEB")
    message("-- Default CPack generator: ${DEFAULT_CPACK_GENERATOR}")
    message("-- Debian package architecture: ${DEBIAN_ARCHITECTURE}")
  endif()
endif()

# Main package

foreach(_DEPEND ${PKG_MAIN_DEPENDS})
  list(GET ${_DEPEND} 0 _PACKAGE)
  list(GET ${_DEPEND} 1 _VERSION_MIN)
  list(APPEND DEBIAN_MAIN_DEPENDS "${_PACKAGE} (>= ${_VERSION_MIN})")
endforeach()

string(JOIN ", " _DEBIAN_MAIN_DEPENDS ${DEBIAN_MAIN_DEPENDS})

set(CPACK_DEBIAN_FILE_NAME            ${PKG_NAME}_${PKG_VERSION}_${DEBIAN_ARCHITECTURE}.deb)
set(CPACK_DEBIAN_PACKAGE_NAME         ${PKG_NAME})
set(CPACK_DEBIAN_PACKAGE_VERSION      ${PKG_VERSION})
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${DEBIAN_ARCHITECTURE})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER   ${PKG_MAINTAINER})
set(CPACK_DEBIAN_PACKAGE_SECTION      misc)
set(CPACK_DEBIAN_PACKAGE_DEPENDS      ${_DEBIAN_MAIN_DEPENDS})

#
# General
#

if (NOT DEFAULT_CPACK_GENERATOR)
  set(DEFAULT_CPACK_GENERATOR ${FALLBACK_CPACK_GENERATOR} CACHE STRING "Default CPack generator")
  message("-- Default CPack generator: ${FALLBACK_CPACK_GENERATOR}")
endif()

set(CPACK_GENERATOR "${DEFAULT_CPACK_GENERATOR}")

include(CPack)

