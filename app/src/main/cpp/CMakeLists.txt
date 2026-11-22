cmake_minimum_required(VERSION 3.22.1)
project(phoenix C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(phoenix SHARED
    phoenix_elf.c
    phoenix_jni.c
)

target_compile_options(phoenix PRIVATE
    -O2
    -Wall
    -Wextra
    -fvisibility=hidden
)

find_library(log-lib log)

target_link_libraries(phoenix
    ${log-lib}
)
