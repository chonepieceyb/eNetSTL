cmake_minimum_required(VERSION 3.10)

project(ebpf_demo_user VERSION 1.0)

set(EXP_LIST "${C_FILES}/test_linked_list_user.c;${C_FILES}/test_time_wheel_user.c")

set(EXECUTABLE_OUTPUT_PATH "${BIN_TARGETS}")

if(EXISTS "${LINUX_PATH}")
    set(LIBBPF_SEARCH_PATH "${LINUX_PATH}/tools/lib/bpf")
else()
    set(LIBBPF_SEARCH_PATH "${LIBBPF_PATH}/src")
endif()

if(${USE_STATIC})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")
    find_library(LIBELF NAMES elf z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
    find_library(LIBZ NAMES z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
    find_library(LIBZSTD NAMES zstd HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
endif()

find_library(LIBBPF NAMES bpf HINTS "${LIBBPF_SEARCH_PATH}" REQUIRED)
find_library(LIBM NAMES m REQUIRED)

file(GLOB BLACK_LIST "${C_FILES}/*.black")
file(GLOB TARGET_LIST "${C_FILES}/*_user.c")
aux_source_directory(${PROJECT_SOURCE_DIR} SRC_LIST)

if(${USE_CMAP})
    aux_source_directory("${C_FILES}/cmaps" CMAP_SRC_LIST)
    file(GLOB CMAP_BLACK_LIST "${C_FILES}/cmaps/*.black")
    file(GLOB CMAP_TARGET_LIST "${C_FILES}/cmaps/*_user.c")
    set(SRC_LIST "${SRC_LIST};${CMAP_SRC_LIST}")
    set(BLACK_LIST "${SRC_LIST};${CMAP_BLACK_LIST}")
    set(TARGET_LIST "${TARGET_LIST};${CMAP_TARGET_LIST}")
endif()

if(${USE_HYPERCOM})
    aux_source_directory("${C_FILES}/hypercom" HC_SRC_LIST)
    file(GLOB HC_BLACK_LIST "${C_FILES}/hypercom/*.black")
    file(GLOB HC_TARGET_LIST "${C_FILES}/hypercom/*_user.c")
    set(SRC_LIST "${SRC_LIST};${HC_SRC_LIST}")
    set(BLACK_LIST "${SRC_LIST};${HC_BLACK_LIST}")
    set(TARGET_LIST "${TARGET_LIST};${HC_TARGET_LIST}")
endif()

if(NOT ${USE_EXP})
    list(REMOVE_ITEM TARGET_LIST ${EXP_LIST})
    list(REMOVE_ITEM SRC_LIST ${EXP_LIST})
endif()

list(REMOVE_ITEM SRC_LIST ${TARGET_LIST})
list(REMOVE_ITEM SRC_LIST ${BLACK_LIST})

foreach(TF ${TARGET_LIST})
    get_filename_component(TN ${TF} NAME_WE)
    add_executable(${TN} ${SRC_LIST} ${TF})

    if(EXISTS "${LINUX_PATH}")
        target_include_directories(${TN} PUBLIC "${LINUX_PATH}/tools/include")
        target_include_directories(${TN} PUBLIC "${LINUX_PATH}/tools/include/uapi")
        target_include_directories(${TN} PUBLIC "${LINUX_PATH}/tools/lib")
    endif()

    if(${USE_STATIC})
        target_link_libraries(${TN} ${LIBBPF} ${LIBM} ${LIBELF} ${LIBZ} ${LIBZSTD})
    else()
        target_link_libraries(${TN} ${LIBBPF} ${LIBM})
    endif()

    add_dependencies(${TN} bpf_skel)
endforeach()

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -O2"
)
