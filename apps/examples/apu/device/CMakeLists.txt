collector_list (_sources APP_COMMON_SOURCES)
list (APPEND _sources "${CMAKE_CURRENT_SOURCE_DIR}/apu.c")

add_library (apu-static STATIC ${_sources})
set_source_files_properties(${_sources} PROPERTIES COMPILE_FLAGS "${_cflags}")
set_target_properties (apu-static PROPERTIES OUTPUT_NAME apu)
install (TARGETS apu-static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

set (OPENAMP_LIB open_amp)
set (LIB_apu apu)
set (_app rity_nn_test)
add_executable (${_app}.elf "${CMAKE_CURRENT_SOURCE_DIR}/test.c")
target_link_libraries(${_app}.elf -Wl,-Map=${_app}.map -Wl,--gc-sections ${_linker_opt} -Wl,--start-group open_amp-static apu-static metal ${_deps} -Wl,--end-group)
install (TARGETS ${_app}.elf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
