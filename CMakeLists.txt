cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
set(CMAKE_C_COMPILER "i686-w64-mingw32-gcc")
set(CMAKE_CXX_COMPILER "i686-w64-mingw32-g++")
set(CMAKE_EXECUTABLE_SUFFIX_CXX ".exe")
set(CMAKE_SHARED_LIBRARY_PREFIX_C "")
set(CMAKE_SHARED_LIBRARY_PREFIX_CXX "")
set(CMAKE_SHARED_LIBRARY_SUFFIX_C ".dll")
set(CMAKE_SHARED_LIBRARY_SUFFIX_CXX ".dll")
set(CMAKE_C_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_CXX_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
add_definitions(-DMINGW_HAS_SECURE_API)


project(mingw_crash_handler)

set_source_files_properties(
  exports.def
  PROPERTIES EXTERNAL_OBJECT 1
)

set(mgwhelp_import_lib_file "${CMAKE_CURRENT_BINARY_DIR}/libmgwhelp.a")

add_custom_command(
    OUTPUT ${mgwhelp_import_lib_file}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/mgwhelp32imp.def
    COMMAND i686-w64-mingw32-dlltool
      -d ${CMAKE_CURRENT_SOURCE_DIR}/mgwhelp32imp.def
      -l ${mgwhelp_import_lib_file}
      -k
)

add_custom_target(mgwhelp_import_lib DEPENDS ${mgwhelp_import_lib_file})

add_library(crash_handler SHARED
  exports.def
  crash_handler.cpp
)

add_dependencies(crash_handler mgwhelp_import_lib)

target_link_libraries(mingw_crash_handler
  ${mgwhelp_import_lib_file}
  -Wl,--enable-stdcall-fixup
  -Wl,--add-stdcall-alias
  -s
)
