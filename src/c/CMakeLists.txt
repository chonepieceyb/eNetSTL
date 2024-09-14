cmake_minimum_required(VERSION 3.10)

project(eurosys_ae VERSION 1.0)

set(EXECUTABLE_OUTPUT_PATH "${BIN_TARGETS}")

if(${USE_STATIC})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")
    find_library(LIBELF NAMES elf z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
    find_library(LIBZ NAMES z HINTS "/usr/lib/x86_64-linux-gnu" REQUIRED)
endif()


find_library(LIBBPF NAMES bpf HINTS "/usr/lib64" REQUIRED)


#exp1-2
aux_source_directory("${C_FILES}/exp1-2" SRC_LIST_EXP1_2)
file(GLOB TARGET_LIST_EXP1_2 "${C_FILES}/exp1-2/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP1_2}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP1_2}")

#exp3
aux_source_directory("${C_FILES}/exp3" SRC_LIST_EXP3)
file(GLOB TARGET_LIST_EXP3 "${C_FILES}/exp3/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP3}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP3}")

#exp4
aux_source_directory("${C_FILES}/exp4" SRC_LIST_EXP4)
file(GLOB TARGET_LIST_EXP4 "${C_FILES}/exp4/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP4}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP4}")

#exp5
aux_source_directory("${C_FILES}/exp5" SRC_LIST_EXP5)
file(GLOB TARGET_LIST_EXP5 "${C_FILES}/exp5/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP5}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP5}")

# #exp6
aux_source_directory("${C_FILES}/exp6" SRC_LIST_EXP6)
file(GLOB TARGET_LIST_EXP6 "${C_FILES}/exp6/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP6}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP6}")

#exp7
aux_source_directory("${C_FILES}/exp7" SRC_LIST_EXP7)
file(GLOB TARGET_LIST_EXP7 "${C_FILES}/exp7/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP7}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP7}")

#exp8
aux_source_directory("${C_FILES}/exp8" SRC_LIST_EXP8)
file(GLOB TARGET_LIST_EXP8 "${C_FILES}/exp8/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP8}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP8}")

#exp9
aux_source_directory("${C_FILES}/exp9" SRC_LIST_EXP9)
file(GLOB TARGET_LIST_EXP9 "${C_FILES}/exp9/*_user.c")
set(SRC_LIST "${SRC_LIST};${SRC_LIST_EXP9}")
set(TARGET_LIST "${TARGET_LIST};${TARGET_LIST_EXP9}")

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
