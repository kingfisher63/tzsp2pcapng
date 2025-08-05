file(STRINGS ${VERSION_FILE} VERSION)

set(SOURCES
  linktype.c
  main.c
  options.c
  outfile.c
  pcap.c
  pcapng.c
  tzsp.c
)

if (${CMAKE_BUILD_TYPE} STREQUAL Debug)
  set(COMPILE_OPTIONS  )
  set(LINK_OPTIONS     --no-undefined)
else ()
  set(COMPILE_OPTIONS  -O2)
  set(LINK_OPTIONS     --no-undefined,--strip-all)
endif()

set(OUTPUT_NAME tzsp2pcapng)
set(TARGET_NAME tzsp2pcapng_exe)

set(CMAKE_C_FLAGS    "-Wall -Wconversion -Wsign-conversion -Wextra")
set(CMAKE_C_STANDARD 17)

add_executable            (${TARGET_NAME} ${SOURCES})
set_target_properties     (${TARGET_NAME} PROPERTIES OUTPUT_NAME ${OUTPUT_NAME} )
target_compile_definitions(${TARGET_NAME} PRIVATE PROGRAM_NAME="${OUTPUT_NAME}" PROGRAM_VERSION="${VERSION}" )
target_compile_options    (${TARGET_NAME} PRIVATE ${COMPILE_OPTIONS})
target_link_options       (${TARGET_NAME} PRIVATE LINKER:${LINK_OPTIONS} -rdynamic)

install(TARGETS ${TARGET_NAME} DESTINATION ${EXE_INSTALL_DIR})
