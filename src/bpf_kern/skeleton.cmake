function(gen_skeleton BPF_TOOL OBJ_INSTALL_DIR SKEL_HEADER_DIR) 
    file(REMOVE_RECURSE ${SKEL_HEADER_DIR})
    file(MAKE_DIRECTORY ${SKEL_HEADER_DIR})
    file(GLOB TARGET_OBJECT_LIST "${OBJ_INSTALL_DIR}/*.o")
    foreach(OBJ_PATH ${TARGET_OBJECT_LIST})
        string(REGEX REPLACE ".+/(.+)\\.o" "\\1" OBJ_NAME ${OBJ_PATH})
        execute_process(COMMAND ${BPF_TOOL} gen skeleton ${OBJ_PATH}
                        OUTPUT_FILE "${SKEL_HEADER_DIR}/${OBJ_NAME}.skel.h")
        message(STATUS "${BPF_TOOL} gen skeleton ${OBJ_PATH}")
        message(STATUS "gen skeleton ${SKEL_HEADER_DIR}/${OBJ_NAME}.skel.h")
    endforeach()
endfunction()

gen_skeleton("${BPF_TOOL_PATH}" "${TARGET_DEST}" "${TARGET_SKEL_HEADER_DIR}")