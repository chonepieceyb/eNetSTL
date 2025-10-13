set(EXECUTABLE_OUTPUT_PATH "${BIN_TARGETS}")

# Get blacklist and whitelist from parent scope or use default
if(NOT DEFINED C_BLACKLIST)
    set(C_BLACKLIST "")
endif()

if(NOT DEFINED C_WHITELIST)
    set(C_WHITELIST "")
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

# Function to check if path is whitelisted (higher priority than blacklist)
function(is_whitelisted path whitelist result)
    set(${result} FALSE PARENT_SCOPE)
    foreach(whitelisted_item ${whitelist})
        if("${path}" MATCHES "${whitelisted_item}")
            set(${result} TRUE PARENT_SCOPE)
            break()
        endif()
    endforeach()
endfunction()

# Function to determine if path should be included (whitelist overrides blacklist)
function(should_include path whitelist blacklist result)
    is_whitelisted("${path}" "${whitelist}" is_in_whitelist)
    is_blacklisted("${path}" "${blacklist}" is_in_blacklist)

    # If whitelist has items, include only whitelisted paths
    # If whitelist is empty, include all paths except blacklisted ones
    if(whitelist)
        if(is_in_whitelist)
            set(${result} TRUE PARENT_SCOPE)
        else()
            set(${result} FALSE PARENT_SCOPE)
        endif()
    else()
        if(is_in_blacklist)
            set(${result} FALSE PARENT_SCOPE)
        else()
            set(${result} TRUE PARENT_SCOPE)
        endif()
    endif()
endfunction()

# Auto-detect all subfolders and compile source files with whitelist/blacklist support
file(GLOB EXP_FOLDERS RELATIVE "${C_FILES}" "${C_FILES}/*")
set(SRC_LIST "")
set(TARGET_LIST "")

foreach(folder ${EXP_FOLDERS})
    set(folder_path "${C_FILES}/${folder}")

    # Skip if not a directory
    if(NOT IS_DIRECTORY "${folder_path}")
        continue()
    endif()

    # Check if folder should be included (whitelist overrides blacklist)
    should_include("${folder}" "${C_WHITELIST}" "${C_BLACKLIST}" include_folder)
    if(NOT include_folder)
        message(STATUS "Excluding C folder: ${folder}")
        continue()
    endif()

    message(STATUS "Including C folder: ${folder}")

    # Get all .c files in the folder
    file(GLOB folder_sources "${folder_path}/*.c")
    file(GLOB user_targets "${folder_path}/*_user.c")

    # Filter files based on whitelist/blacklist for sources
    foreach(source ${folder_sources})
        get_filename_component(source_name "${source}" NAME)
        should_include("${folder}/${source_name}" "${C_WHITELIST}" "${C_BLACKLIST}" include_file)
        if(include_file)
            list(APPEND SRC_LIST "${source}")
        else()
            message(STATUS "Excluding C source file: ${folder}/${source_name}")
        endif()
    endforeach()

    # Filter files based on whitelist/blacklist for targets
    foreach(target ${user_targets})
        get_filename_component(target_name "${target}" NAME)
        should_include("${folder}/${target_name}" "${C_WHITELIST}" "${C_BLACKLIST}" include_target)
        if(include_target)
            list(APPEND TARGET_LIST "${target}")
        else()
            message(STATUS "Excluding C target file: ${folder}/${target_name}")
        endif()
    endforeach()
endforeach()

# Remove target files and files with main functions from source list to avoid duplication
list(REMOVE_ITEM SRC_LIST ${TARGET_LIST})

# Also exclude files that match target patterns ( *_user.c ) from source list
foreach(source ${SRC_LIST})
    get_filename_component(source_name "${source}" NAME)
    if("${source_name}" MATCHES "_user\\.c$")
        list(REMOVE_ITEM SRC_LIST "${source}")
    endif()
endforeach()

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
