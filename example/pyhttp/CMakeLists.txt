CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
MESSAGE(STATUS "CMake version: ${CMAKE_VERSION}")

PROJECT(pyhttp)

IF(NOT DEFINED PY_CONFIG)
    MESSAGE(FATAL_ERROR "must -DPY_CONFIG=\"python-config path\"")
ENDIF()

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build Type ${CMAKE_BUILD_TYPE}")

EXECUTE_PROCESS(
    COMMAND ${PY_CONFIG} --includes
    COMMAND awk "{print $2}"
    COMMAND cut -c 3-
    OUTPUT_VARIABLE PY_INC
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
    COMMAND ${PY_CONFIG} --prefix
    COMMAND awk "{print $1\"/lib\"}"
    OUTPUT_VARIABLE PY_LIB_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
# find /application/Python-3.9.17/lib -maxdepth 1 -name "lib*.so"|rev|cut -d / -f 1|rev|cut -c 4-|rev|cut -c 4-|rev
EXECUTE_PROCESS(
    COMMAND find ${PY_LIB_DIR} -maxdepth 1 -name "lib*.so"
    COMMAND head -n 1
    COMMAND rev
    COMMAND cut -d / -f 1
    COMMAND rev
    COMMAND cut -c 4-
    COMMAND rev
    COMMAND cut -c 4-
    COMMAND rev
    OUTPUT_VARIABLE PY_LIB_NAME
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# include python headers
MESSAGE(STATUS "Python Include Path ${PY_INC}")
INCLUDE_DIRECTORIES(${PY_INC})

# link python libs
MESSAGE(STATUS "Python Library ${PY_LIB_DIR}")
MESSAGE(STATUS "Python Libs ${PY_LIB_NAME}")
FIND_LIBRARY(PY_LIB
    NAMES "${PY_LIB_NAME}"
    PATHS "${PY_LIB_DIR}"
)
LINK_LIBRARIES(${PY_LIB})


INCLUDE_DIRECTORIES(./src)
INCLUDE_DIRECTORIES(../../src)

SET(SRC
    src/entry.c
    ../../src/core/log.c
    ../../src/core/module.c
    ../../src/server/server.c
)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRC})
