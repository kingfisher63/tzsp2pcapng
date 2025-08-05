set(MAN_PAGES
  tzsp2pcapng.8
)

set(TARGET_NAME  tzsp2pcapng_man)

set(MAN_DIR      "${CMAKE_CURRENT_LIST_DIR}")
set(MAN_GZ_DIR   "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${TARGET_NAME}.dir")

foreach(MAN_PAGE ${MAN_PAGES})
  cmake_path(GET MAN_PAGE EXTENSION LAST_ONLY MAN_PAGE_EXT)
  string(SUBSTRING ${MAN_PAGE_EXT} 1 1 MAN_SECTION)

  set(MAN_FILE     "${MAN_DIR}/${MAN_PAGE}")
  set(MAN_GZ_FILE  "${MAN_GZ_DIR}/${MAN_PAGE}.gz")

  add_custom_command(
    OUTPUT    ${MAN_GZ_FILE}
    DEPENDS   ${MAN_FILE}
    COMMAND   gzip --stdout ${MAN_FILE} > ${MAN_GZ_FILE}
    VERBATIM
  )

  install(
    FILES        ${MAN_GZ_FILE}
    DESTINATION  ${MAN_INSTALL_DIR}/man${MAN_SECTION}
  )

  list(APPEND MAN_GZ_FILES ${MAN_GZ_FILE}) 
endforeach()

add_custom_target(
  ${TARGET_NAME}
  ALL
  DEPENDS  ${MAN_GZ_FILES}
)

