set(MAN8_PAGES
  tzsp2pcapng.8
)

set(MAN8_PAGES_GZ
  tzsp2pcapng.8.gz
)

set(TARGET_NAME tzsp2pcapng_man)

add_custom_target(
  ${TARGET_NAME}
  ALL
  DEPENDS ${MAN8_PAGES}
)

add_custom_command(
  TARGET             ${TARGET_NAME}
  WORKING_DIRECTORY  ${CMAKE_CURRENT_LIST_DIR}
  COMMAND            gzip -f -k ${MAN8_PAGES}
  OUTPUTS            ${MAN8_PAGES_GZ}
)

install(
  FILES        ${MAN8_PAGES_GZ}
  DESTINATION  ${MAN_INSTALL_DIR}/man8
)
