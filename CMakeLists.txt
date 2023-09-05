CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
MESSAGE(STATUS "CMake version: ${CMAKE_VERSION}")

PROJECT(sge-service)

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build Type ${CMAKE_BUILD_TYPE}")

SET(EPOLL_FILE "")
SET(IOURING_FILE "")
SET(WITH_EPOLL 1)

IF(${WITHOUT_EPOLL})
    SET(WITH_EPOLL 0)
ELSE()
    SET(EPOLL_FILE "src/event/epoll.c")
ENDIF()

IF(${WITH_IO_URING})
    SET(WITH_IO_URING 1)
    SET(IOURING_FILE "src/event/io_uring.c")

    SET(LIBURING_SRC_DIR ${CMAKE_SOURCE_DIR}/src/third/liburing)
    SET(LIBURING_OUTPUT_DIR ${LIBURING_SRC_DIR}/src)
    SET(LIBURING_LIBRARY ${LIBURING_OUTPUT_DIR}/liburing.a)

    MESSAGE(STATUS "LIBURING_SRC_DIR ${LIBURING_SRC_DIR}")

    ADD_CUSTOM_TARGET(build_liburing
        COMMAND cd ${LIBURING_SRC_DIR}
        COMMAND chmod +x ./configure
        COMMAND make
        WORKING_DIRECTORY ${LIBURING_SRC_DIR}
        COMMENT "build liburing target"
    )

    ADD_LIBRARY(liburing STATIC IMPORTED)
    SET_PROPERTY(TARGET liburing APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
    SET_TARGET_PROPERTIES(liburing PROPERTIES IMPORTED_LOCATION_NOCONFIG "${LIBURING_LIBRARY}")
    ADD_DEPENDENCIES(liburing build_liburing)

    INCLUDE_DIRECTORIES(${LIBURING_OUTPUT_DIR})

    LINK_LIBRARIES(liburing)
ELSE()
    SET(WITH_IO_URING 0)
ENDIF()

#
# set include path
#
INCLUDE_DIRECTORIES(./src)
INCLUDE_DIRECTORIES(./src/third/ini/src)
INCLUDE_DIRECTORIES(./src/third/libcontext)

#
# set output dir
#
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#
# generate const.h file
#
CONFIGURE_FILE(
    "${PROJECT_SOURCE_DIR}/const.h.in"
    "${PROJECT_SOURCE_DIR}/src/core/const.h"
)

# pthread
SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-pthread -g -Werror -Wall -Wextra")
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-pthread -g -Werror -Wall -Wextra")
LINK_LIBRARIES(${CMAKE_DL_LIBS})

SET(SRC
    src/core/log.c
    src/core/dict.c
    src/core/string.c
    src/core/queue.c
    src/core/module.c
    src/core/event.c
    src/core/res_pool.c

    src/third/ini/src/ini.c
    src/third/libcontext/libcontext.cpp

    src/server/cond.c
    src/server/server.c
    src/task/task.cpp
    ${EPOLL_FILE}
    ${IOURING_FILE}

    src/config.c
    src/main.c
)

ADD_EXECUTABLE(${PROJECT_NAME} ${SRC})

INSTALL(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
