set(EXECUTABLE_OUTPUT_PATH "${BIN_TARGETS}")

# Get blacklist from parent scope or use default
if(NOT DEFINED C_BLACKLIST)
    set(C_BLACKLIST "")
endif()


# Add custom libbpf search path support
if(${USE_STATIC})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")
    find_library(LIBELF NAMES elf z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
    find_library(LIBZ NAMES z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
endif()

# Search for libbpf in custom Linux path or system paths
if(USE_CUSTOM_LINUX AND LINUX_PATH AND NOT "${LINUX_PATH}" STREQUAL "NONE")
    # Try to find libbpf in custom Linux path first
    find_library(LIBBPF NAMES bpf
        HINTS
            "${LINUX_PATH}/tools/lib/bpf"
        REQUIRED
    )
    message(STATUS "Looking for libbpf in: ${LINUX_PATH}/tools/lib/bpf")
else()
    # Use system libbpf
    find_library(LIBBPF NAMES bpf HINTS "/usr/lib64" REQUIRED)
    message(STATUS "Using system libbpf")
endif()

# Function to check if path is blacklisted
function(is_blacklisted path blacklist result)
    set(${result} FALSE PARENT_SCOPE)
    foreach(blacklisted_item ${blacklist})
        if("${path}" MATCHES "${blacklisted_item}")
            set(${result} TRUE PARENT_SCOPE)
            break()
        endif()
    endforeach()
endfunction()

# Auto-detect all subfolders and compile source files with blacklist support
file(GLOB EXP_FOLDERS RELATIVE "${C_FILES}" "${C_FILES}/*")
set(SRC_LIST "")
set(TARGET_LIST "")

foreach(folder ${EXP_FOLDERS})
    set(folder_path "${C_FILES}/${folder}")

    # Skip if not a directory
    if(NOT IS_DIRECTORY "${folder_path}")
        continue()
    endif()

    # Check if folder is blacklisted
    is_blacklisted("${folder}" "${C_BLACKLIST}" is_excluded)
    if(is_excluded)
        message(STATUS "Excluding C folder: ${folder}")
        continue()
    endif()

    message(STATUS "Including C folder: ${folder}")

    # Get all .c files in the folder
    file(GLOB folder_sources "${folder_path}/*.c")
    file(GLOB user_targets "${folder_path}/*_user.c")

    # Filter out blacklisted individual files from sources
    foreach(source ${folder_sources})
        get_filename_component(source_name "${source}" NAME)
        is_blacklisted("${folder}/${source_name}" "${C_BLACKLIST}" file_excluded)
        if(NOT file_excluded)
            list(APPEND SRC_LIST "${source}")
        else()
            message(STATUS "Excluding C source file: ${folder}/${source_name}")
        endif()
    endforeach()

    # Filter out blacklisted individual files from targets
    foreach(target ${user_targets})
        get_filename_component(target_name "${target}" NAME)
        is_blacklisted("${folder}/${target_name}" "${C_BLACKLIST}" target_excluded)
        if(NOT target_excluded)
            list(APPEND TARGET_LIST "${target}")
        else()
            message(STATUS "Excluding C target file: ${folder}/${target_name}")
        endif()
    endforeach()
endforeach()

# Remove target files from source list to avoid duplication
list(REMOVE_ITEM SRC_LIST ${TARGET_LIST})

foreach(TF ${TARGET_LIST})
    get_filename_component(TN ${TF} NAME_WE)
    add_executable(${TN} ${SRC_LIST} ${TF})
    if(${USE_STATIC})
        target_link_libraries(${TN} ${LIBBPF} ${LIBM} ${LIBELF} ${LIBZ})
    else()
        target_link_libraries(${TN} ${LIBBPF} ${LIBM})
    endif()
    add_dependencies(${TN} bpf_skel)
endforeach()


set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -O2"
)
