cmake_minimum_required(VERSION 3.15)

set(CMAKE_C_COMPILER "/usr/bin/clang-15")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(eurosys_ae VERSION 0.1)

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")
set(BIN_TARGETS "${PROJECT_SOURCE_DIR}/bin")

# some custom vars
set(BPF_KERN_SRC_FILES "${PROJECT_SOURCE_DIR}/src/bpf_kern")
set(BPF_KERN_TARGETS "${CMAKE_INSTALL_PREFIX}/bpf_kern_objs")
set(BPF_SKEL_HEADERS "${PROJECT_SOURCE_DIR}/src/c/bpf_skel")
set(BIN_TARGETS "${PROJECT_SOURCE_DIR}/bin")
set(C_FILES "${PROJECT_SOURCE_DIR}/src/c")

# compile options

set(USE_STATIC OFF CACHE BOOL "should compile with static library")
message(STATUS "USE_STATIC: ${USE_STATIC}")

set(LOG_LEVEL 2 CACHE STRING "set log level")
add_compile_definitions(LOG_LEVEL=${LOG_LEVEL})
message(STATUS "LOG_LEVEL: ${LOG_LEVEL}")

set(USE_LATENCY_EXP OFF CACHE BOOL "start latency evaluations")
message(STATUS "LATENCY_EXP: ${USE_LATENCY_EXP}")
if(${USE_LATENCY_EXP})
    add_compile_definitions(LATENCY_EXP=1)
endif()

add_subdirectory("${BPF_KERN_SRC_FILES}")
add_subdirectory("${C_FILES}")