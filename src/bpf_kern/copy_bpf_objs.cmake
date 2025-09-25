#TDOO: if copy failed, stop compile process
function(rename_and_copy OBJS DEST)
    if (NOT EXISTS ${DEST})
        file(MAKE_DIRECTORY ${DEST})
    endif()
    foreach(OBJ_PATH ${OBJS})
        string(REGEX REPLACE ".+/(.+)" "\\1" OBJ_NAME ${OBJ_PATH})
        string(REPLACE ".c." "." NEW_OBJ_NAME ${OBJ_NAME})
        file(COPY_FILE ${OBJ_PATH} ${DEST}/${NEW_OBJ_NAME})
        message(STATUS "copy ${OBJ_PATH} to ${DEST}/${NEW_OBJ_NAME}")
    endforeach()
endfunction()

rename_and_copy("${TARGET_OBJS}" "${TARGET_DEST}")