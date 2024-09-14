cmake_minimum_required(VERSION 3.10)

project(eurosys_ae VERSION 0.1)

#exp1-2
aux_source_directory("${BPF_KERN_SRC_FILES}/exp1-2" BPF_SRC_LIST_EXP1_2)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP1_2}")

#exp3
aux_source_directory("${BPF_KERN_SRC_FILES}/exp3" BPF_SRC_LIST_EXP3)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP3}")

#exp4
aux_source_directory("${BPF_KERN_SRC_FILES}/exp4" BPF_SRC_LIST_EXP4)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP4}")

#exp5
aux_source_directory("${BPF_KERN_SRC_FILES}/exp5" BPF_SRC_LIST_EXP5)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP5}")

#exp6
aux_source_directory("${BPF_KERN_SRC_FILES}/exp6" BPF_SRC_LIST_EXP6)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP6}")

#exp7
aux_source_directory("${BPF_KERN_SRC_FILES}/exp7" BPF_SRC_LIST_EXP7)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP7}")

#exp8
aux_source_directory("${BPF_KERN_SRC_FILES}/exp8" BPF_SRC_LIST_EXP8)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP8}")

#exp9
aux_source_directory("${BPF_KERN_SRC_FILES}/exp9" BPF_SRC_LIST_EXP9)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_EXP9}")

#utils
aux_source_directory("${BPF_KERN_SRC_FILES}/utils" BPF_SRC_LIST_UTILS)
set(BPF_SRC_LIST "${BPF_SRC_LIST};${BPF_SRC_LIST_UTILS}")

#compile all .o files
add_library(eurosys_ae OBJECT ${BPF_SRC_LIST})

#install(FILES $<TARGET_OBJECTS:eurosys_ae> DESTINATION "${BPF_KERN_TARGETS}")
add_custom_target(bpf_copy ALL
    COMMAND "${CMAKE_COMMAND}"
          -DTARGET_OBJS="$<TARGET_OBJECTS:eurosys_ae>"
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
          -DTARGET_OBJS="$<TARGET_OBJECTS:eurosys_ae>"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bpf_objs.cmake"
    COMMAND "${CMAKE_COMMAND}"
          -DBPF_TOOL_PATH="${BPF_TOOL}"
          -DTARGET_DEST="${BPF_KERN_TARGETS}"
          -DTARGET_SKEL_HEADER_DIR="${BPF_SKEL_HEADERS}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/skeleton.cmake"
)

add_dependencies(bpf_copy eurosys_ae)
add_dependencies(bpf_skel bpf_copy)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -g -O2 -target bpf"
)