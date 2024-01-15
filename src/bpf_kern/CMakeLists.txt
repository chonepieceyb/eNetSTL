cmake_minimum_required(VERSION 3.10)

project(ebpf_demos VERSION 0.1)

file(GLOB BLACK_LIST "${BPF_KERN_SRC_FILES}/*.black")
aux_source_directory("${BPF_KERN_SRC_FILES}" BPF_SRC_LIST)

set(EXP_LIST 
"${BPF_KERN_SRC_FILES}/linked_list_test.c;${BPF_KERN_SRC_FILES}/sched_time_wheel.c"
)

if(${USE_CMAP})
    aux_source_directory("${BPF_KERN_SRC_FILES}/cmaps" BPF_SRC_LIST_CMAP)
    file(GLOB BLACK_LIST_CMAP "${BPF_KERN_SRC_FILES}/cmaps/*.black")
    set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_CMAP}")
    set(BLACK_LIST "${BLACK_LIST};${BLACK_LIST_CMAP}")
endif()

if(${USE_HYPERCOM})
    aux_source_directory("${BPF_KERN_SRC_FILES}/hypercom" BPF_SRC_LIST_HC)
    file(GLOB BLACK_LIST_HC "${BPF_KERN_SRC_FILES}/hypercom/*.black")
    set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_HC}")
    set(BLACK_LIST "${BLACK_LIST};${BLACK_LIST_HC}")
endif()

if (NOT ${USE_EXP})
    list(REMOVE_ITEM BPF_SRC_LIST ${EXP_LIST})
endif()

list(REMOVE_ITEM BPF_SRC_LIST ${BLACK_LIST})

#compile all .o files
add_library(ebpf_demo OBJECT ${BPF_SRC_LIST})

if (EXISTS "${LINUX_PATH}")
    target_include_directories(ebpf_demo PUBLIC "${LINUX_PATH}/tools/lib/bpf")
    set(BPF_TOOL "${LINUX_PATH}/tools/bpf/bpftool/bpftool")
else()
    target_include_directories(ebpf_demo PUBLIC "${LIBBPF_PATH}/src")
    set(BPF_TOOL "${BPF_TOOL_PATH}/src/bpftool")
endif()

#install(FILES $<TARGET_OBJECTS:ebpf_demo> DESTINATION "${BPF_KERN_TARGETS}")
add_custom_target(bpf_copy ALL
    COMMAND "${CMAKE_COMMAND}"
          -DTARGET_OBJS="$<TARGET_OBJECTS:ebpf_demo>"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bpf_objs.cmake"
)

add_custom_target(bpf_skel ALL
    COMMAND "${CMAKE_COMMAND}"
          -DBPF_TOOL_PATH="${BPF_TOOL}"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -DTARGET_SKEL_HEADER_DIR="${BPF_SKEL_HEADERS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/skeleton.cmake"
)

add_custom_target(bpf_install
    COMMAND "${CMAKE_COMMAND}"
          -DTARGET_OBJS="$<TARGET_OBJECTS:ebpf_demo>"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bpf_objs.cmake"
    COMMAND "${CMAKE_COMMAND}"
          -DBPF_TOOL_PATH="${BPF_TOOL}"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -DTARGET_SKEL_HEADER_DIR="${BPF_SKEL_HEADERS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/skeleton.cmake"
)

add_dependencies(bpf_copy ebpf_demo)
add_dependencies(bpf_skel bpf_copy)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -g -O2 -target bpf"
)
