cmake_minimum_required(VERSION 3.15)
project(JWTAuthServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2)

file(GLOB_RECURSE SOURCES "src/*.cpp")
include_directories(include)

add_executable(jwt_auth_server ${SOURCES})

# Линкуем с SQLite
target_link_libraries(jwt_auth_server sqlite3)
