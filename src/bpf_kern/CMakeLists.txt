# Get blacklist from parent scope or use default
if(NOT DEFINED BPF_BLACKLIST)
    set(BPF_BLACKLIST "")
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
file(GLOB EXP_FOLDERS RELATIVE "${BPF_KERN_SRC_FILES}" "${BPF_KERN_SRC_FILES}/*")
set(BPF_SRC_LIST "")

foreach(folder ${EXP_FOLDERS})
    set(folder_path "${BPF_KERN_SRC_FILES}/${folder}")

    # Skip if not a directory
    if(NOT IS_DIRECTORY "${folder_path}")
        continue()
    endif()

    # Check if folder is blacklisted
    is_blacklisted("${folder}" "${BPF_BLACKLIST}" is_excluded)
    if(is_excluded)
        message(STATUS "Excluding BPF folder: ${folder}")
        continue()
    endif()

    message(STATUS "Including BPF folder: ${folder}")

    # Get all .c files in the folder
    file(GLOB folder_sources "${folder_path}/*.c")

    # Filter out blacklisted individual files
    foreach(source ${folder_sources})
        get_filename_component(source_name "${source}" NAME)
        is_blacklisted("${folder}/${source_name}" "${BPF_BLACKLIST}" file_excluded)
        if(NOT file_excluded)
            list(APPEND BPF_SRC_LIST "${source}")
        else()
            message(STATUS "Excluding BPF file: ${folder}/${source_name}")
        endif()
    endforeach()
endforeach()

#compile all .o files
add_library(${PROJECT_NAME} OBJECT ${BPF_SRC_LIST})

# Add custom Linux headers and bpftool support
if(USE_CUSTOM_LINUX AND LINUX_PATH AND NOT "${LINUX_PATH}" STREQUAL "NONE")
    # Add custom Linux headers include path using target_include_directories
    target_include_directories(${PROJECT_NAME} PRIVATE "${LINUX_PATH}/tools/lib")
    message(STATUS "Using custom Linux headers from: ${LINUX_PATH}/tools/lib")

    # Set custom bpftool path
    set(BPF_TOOL "${LINUX_PATH}/tools/bpf/bpftool/bpftool")
    message(STATUS "Using custom bpftool: ${BPF_TOOL}")
else()
    # Use system bpftool
    set(BPF_TOOL "bpftool")
    message(STATUS "Using system bpftool")
endif()

#install(FILES $<TARGET_OBJECTS:${PROJECT_NAME}> DESTINATION "${BPF_KERN_TARGETS}")
add_custom_target(bpf_copy ALL
    COMMAND "${CMAKE_COMMAND}"
          -DTARGET_OBJS="$<TARGET_OBJECTS:${PROJECT_NAME}>"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bpf_objs.cmake"
)

add_custom_target(bpf_skel ALL
    COMMAND "${CMAKE_COMMAND}"
          -DBPF_TOOL_PATH="bpftool"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -DTARGET_SKEL_HEADER_DIR="${BPF_SKEL_HEADERS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/skeleton.cmake"
)

add_custom_target(bpf_install
    COMMAND "${CMAKE_COMMAND}"
          -DTARGET_OBJS="$<TARGET_OBJECTS:${PROJECT_NAME}>"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bpf_objs.cmake"
    COMMAND "${CMAKE_COMMAND}"
          -DBPF_TOOL_PATH="${BPF_TOOL}"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -DTARGET_SKEL_HEADER_DIR="${BPF_SKEL_HEADERS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/skeleton.cmake"
)

add_dependencies(bpf_copy ${PROJECT_NAME})
add_dependencies(bpf_skel bpf_copy)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -g -O2 -target bpf"
)