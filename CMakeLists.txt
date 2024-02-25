cmake_minimum_required(VERSION 3.15)

set(CMAKE_C_COMPILER "/usr/bin/clang-15")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(ebpf_demos VERSION 0.1)

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")
set(BIN_TARGETS "${PROJECT_SOURCE_DIR}/bin")
set(LINUX_PATH "${PROJECT_SOURCE_DIR}/linux/")
set(LIBBPF_PATH "${PROJECT_SOURCE_DIR}/deps/libbpf")
set(BPF_TOOL_PATH "${PROJECT_SOURCE_DIR}/deps/bpftool")

# some custom vars
set(BPF_KERN_SRC_FILES "${PROJECT_SOURCE_DIR}/src/bpf_kern")
set(BPF_KERN_TARGETS "${CMAKE_INSTALL_PREFIX}/bpf_kern_objs")
set(BPF_SKEL_HEADERS "${PROJECT_SOURCE_DIR}/src/c/bpf_skel")
set(BIN_TARGETS "${PROJECT_SOURCE_DIR}/bin")
set(C_FILES "${PROJECT_SOURCE_DIR}/src/c")

if(EXISTS "${LINUX_PATH}")
    message(STATUS "using libbpf in ${LINUX_PATH}")
else()
    message(STATUS "using libbpf in ${LIBBPF_PATH}")
endif()

# compile options
set(USE_CMAP OFF CACHE BOOL "should compile cmap")
message(STATUS "USE_CMAP: ${USE_CMAP}")

set(USE_EXP ON CACHE BOOL "should compile experimental")
message(STATUS "USE_EXP: ${USE_EXP}")

set(USE_HYPERCOM OFF CACHE BOOL "should compile hypercom")
message(STATUS "USE_HYPERCOM: ${USE_HYPERCOM}")

set(LOG_LEVEL 2 CACHE STRING "should compile cmap")
add_compile_definitions(LOG_LEVEL=${LOG_LEVEL})

set(USE_STATIC OFF CACHE BOOL "should compile with static library")
message(STATUS "USE_STATIC: ${USE_STATIC}")

set(USE_IMPL 0 CACHE STRING "type of implementation used")
message(STATUS "USE_IMPL: ${USE_IMPL}")
add_compile_definitions(USE_IMPL=${USE_IMPL})

set(USE_LOOKUP_ONLY OFF CACHE BOOL "should lookup only and never update")
message(STATUS "USE_LOOKUP_ONLY: ${USE_LOOKUP_ONLY}")

if(${USE_LOOKUP_ONLY})
    add_compile_definitions(USE_LOOKUP_ONLY)
endif()

message(STATUS "LOG_LEVEL: ${LOG_LEVEL}")

add_subdirectory("${BPF_KERN_SRC_FILES}")
add_subdirectory("${C_FILES}")