set(MAN8_PAGES
  tzsp2pcapng.8
)

set(MAN8_PAGES_GZ
  tzsp2pcapng.8.gz
)

set(MAN_INSTALL_DIR local/share/man)  # You can adjust this or pass from top CMakeLists.txt

# Custom command to gzip the man page
add_custom_command(
  OUTPUT ${MAN8_PAGES_GZ}
  COMMAND gzip -f -k ${MAN8_PAGES}
  DEPENDS ${MAN8_PAGES}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compressing man page ${MAN8_PAGES} to ${MAN8_PAGES_GZ}"
  VERBATIM
)

# Custom target that depends on the compressed man page
add_custom_target(
  ${TARGET_NAME} ALL
  DEPENDS ${MAN8_PAGES_GZ}
)

# Install the gzipped man page
install(
  FILES ${MAN8_PAGES_GZ}
  DESTINATION ${MAN_INSTALL_DIR}/man8
)
