set (_cflags "${CMAKE_C_FLAGS} ${APP_EXTRA_C_FLAGS} -fdata-sections -ffunction-sections \
	-I${CMAKE_CURRENT_SOURCE_DIR}/include")
set (_fw_dir "${APPS_SHARE_DIR}")

collector_list (_list PROJECT_INC_DIRS)
collector_list (_app_list APP_INC_DIRS)
include_directories (${_list} ${_app_list} ${CMAKE_CURRENT_SOURCE_DIR}/include)

collector_list (_list PROJECT_LIB_DIRS)
collector_list (_app_list APP_LIB_DIRS)
link_directories (${_list} ${_app_list})

get_property (_linker_opt GLOBAL PROPERTY APP_LINKER_OPT)
collector_list (_deps PROJECT_LIB_DEPS)

set (OPENAMP_LIB open_amp)

add_subdirectory(device)
