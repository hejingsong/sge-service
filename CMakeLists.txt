CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
MESSAGE(STATUS "CMake version: ${CMAKE_VERSION}")

PROJECT(sge-service)

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build Type ${CMAKE_BUILD_TYPE}")

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
# generate config.h file
#
CONFIGURE_FILE(
    "${PROJECT_SOURCE_DIR}/config.h.in"
    "${PROJECT_SOURCE_DIR}/src/core/config.h"
)

#
# event library
#
ADD_SUBDIRECTORY(./src/event/epoll)
IF(${WITH_IOURING})
    IF(${WITH_IOURING} STREQUAL "yes")
        MESSAGE(STATUS "enable io uring event manager")
        ADD_SUBDIRECTORY(./src/event/io_uring)
    ELSE()
        MESSAGE(STATUS "unknown io_uring variable")
    ENDIF()
ELSE()
    MESSAGE(STATUS "without io uring event manager")
ENDIF()

# pthread
SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-pthread -g")
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-pthread -g")
LINK_LIBRARIES(${CMAKE_DL_LIBS})

SET(SRC
    src/core/log.c
    src/core/dict.c
    src/core/buffer.c
    src/core/queue.c
    src/core/res_pool.c

    src/third/ini/src/ini.c
    src/third/libcontext/libcontext.cpp

    src/utils/config.c

    src/event/event_pool.c
    src/event/event_mgr.c

    src/task/task_mgr.cpp
    src/task/task_controller.c

    src/server/server.c
    src/server/acceptor.c
    src/server/connection.c
    src/server/socket.c

    src/module/module.c

    src/main.c
)

ADD_EXECUTABLE(${PROJECT_NAME} ${SRC})

INSTALL(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
