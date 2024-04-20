cmake_minimum_required(VERSION 3.28)
project(loginpp)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
    add_compile_options(-fcolor-diagnostics)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
endif ()

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

include(cmake/CPM.cmake)
CPMAddPackage("gh:p-ranav/argparse@3.0")

add_library(loginpp SHARED
  src/client.cpp
  src/client_factory.cpp
  src/ftp.cpp
  src/mysql.cpp
  src/postgresql.cpp
  src/sftp.cpp
  src/telnet.cpp
)

target_link_libraries(loginpp ${Boost_LIBRARIES})
target_link_libraries(loginpp OpenSSL::SSL OpenSSL::Crypto)
# libssh2
target_link_options(loginpp INTERFACE -lssh2)

add_executable(cli src/main.cpp)
target_link_libraries(cli loginpp)
target_link_libraries(cli argparse)
