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

# Blacklist config files for selective compilation
set(BPF_BLACKLIST_FILE "${PROJECT_SOURCE_DIR}/cmake/bpf_blacklist.txt" CACHE FILEPATH "Path to BPF blacklist file (contains folders/files to exclude)")
set(C_BLACKLIST_FILE "${PROJECT_SOURCE_DIR}/cmake/c_blacklist.txt" CACHE FILEPATH "Path to C blacklist file (contains folders/files to exclude)")

# Linux kernel source path option
set(LINUX_PATH "${PROJECT_SOURCE_DIR}/linux" CACHE PATH "Path to Linux kernel source directory")

# Detect if Linux folder exists, if not set to NONE (use system libbpf)
if(EXISTS "${LINUX_PATH}" AND IS_DIRECTORY "${LINUX_PATH}")
    message(STATUS "LINUX_PATH: ${LINUX_PATH} (found)")
    set(USE_CUSTOM_LINUX ON CACHE BOOL "Use custom Linux kernel source")
    add_compile_definitions(USE_CUSTOM_LINUX=1)
else()
    message(STATUS "LINUX_PATH: ${LINUX_PATH} (not found, using system libbpf)")
    set(LINUX_PATH "NONE" CACHE STRING "Linux source not found, using system libbpf" FORCE)
    set(USE_CUSTOM_LINUX OFF CACHE BOOL "Use custom Linux kernel source")
    # Use COMPILE_DEFINITIONS property instead of remove_compile_definitions
    get_directory_property(CURRENT_DEFINITIONS COMPILE_DEFINITIONS)
    if(CURRENT_DEFINITIONS)
        list(REMOVE_ITEM CURRENT_DEFINITIONS "USE_CUSTOM_LINUX")
        set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${CURRENT_DEFINITIONS}")
    endif()
endif()

# Function to read blacklist file
function(read_blacklist file_path output_var)
    set(${output_var} "" PARENT_SCOPE)
    if(EXISTS "${file_path}")
        file(STRINGS "${file_path}" blacklist_lines)
        foreach(line ${blacklist_lines})
            # Skip empty lines and comments
            if(NOT "${line}" MATCHES "^[[:space:]]*#.*$" AND NOT "${line}" MATCHES "^[[:space:]]*$")
                list(APPEND ${output_var} "${line}")
            endif()
        endforeach()
        set(${output_var} "${${output_var}}" PARENT_SCOPE)
    endif()
endfunction()

# Read blacklist files
read_blacklist("${BPF_BLACKLIST_FILE}" BPF_BLACKLIST)
read_blacklist("${C_BLACKLIST_FILE}" C_BLACKLIST)

message(STATUS "BPF blacklist: ${BPF_BLACKLIST}")
message(STATUS "C blacklist: ${C_BLACKLIST}")

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

# Add a custom target to show build success information
add_custom_target(build_info ALL
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== eNetSTL Build Completed Successfully! ==="
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "📁 User-space programs:      ${PROJECT_SOURCE_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E echo "📁 BPF objects:             ${CMAKE_INSTALL_PREFIX}/bpf_kern_objs"
    COMMAND ${CMAKE_COMMAND} -E echo "📁 BPF skeleton headers:     ${PROJECT_SOURCE_DIR}/src/c/bpf_skel"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "🚀 Ready to run eNetSTL experiments!"
    VERBATIM
)

# Make build_info depend on BPF library
if(TARGET eurosys_ae)
    add_dependencies(build_info eurosys_ae)
endif()

# Add dependencies for all generated executables
get_directory_property(TARGET_LIST DIRECTORY ${C_FILES} BUILDSYSTEM_TARGETS)
foreach(TARGET_NAME ${TARGET_LIST})
    if(TARGET ${TARGET_NAME} AND NOT ${TARGET_NAME} MATCHES "^build_info$")
        add_dependencies(build_info ${TARGET_NAME})
    endif()
endforeach()