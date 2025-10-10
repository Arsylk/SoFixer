cmake_minimum_required(VERSION 3.10)
project(SoFixer)

# Use modern C++
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CC aarch64-linux-android24-clang)
set(CMAKE_CCX aarch64-linux-android24-clang++)

# =========================================================
# SoFixer options
# =========================================================
# set(SO_64 OFF CACHE BOOL "build SoFixer for 64bit target")

if(true)
    message("building SoFixer for 64bit target")
    add_definitions("-D__SO64__")
    set(TARGET_NAME SoFixer64)
else()
    message("building SoFixer for 32bit target")
    add_definitions("-D__SO32__")
    set(TARGET_NAME SoFixer32)
endif()

# Make a static library (.a) containing the core logic, link executable from it
add_library(sofixer_core STATIC ElfReader.cpp
        ElfRebuilder.cpp
        ObElfReader.cpp)

# Enable position-independent code for static library to ease linking to shared libs
set_target_properties(sofixer_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The executable links to the static library
add_executable(${TARGET_NAME} main.cpp)
target_link_libraries(${TARGET_NAME} PRIVATE sofixer_core)
    
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -g -fPIC -Oz -static-libgcc ")
# if(MINGW)
#     message("build with mingw")
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
# endif()

# set(ROOT_SRC ElfReader.cpp
#         ElfRebuilder.cpp
#         ObElfReader.cpp)

# add_executable(${TARGET_NAME} ${ROOT_SRC} main.cpp)

