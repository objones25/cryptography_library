# Main CMakeLists.txt
cmake_minimum_required(VERSION 3.12)
project(cryptography_library VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

# Check for x86_64 architecture and add AES-NI flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64)|(AMD64)|(^i.86$)")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-maes -msse4.1)
    elseif(MSVC)
        add_compile_definitions(_M_X64)
    endif()
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# List of source files
add_library(crypto
    src/symmetric.cpp
    src/crypto_logger.cpp
    src/hash.cpp
)

# Include directories
target_include_directories(crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link against threads
target_link_libraries(crypto PRIVATE Threads::Threads)

# Installation rules
install(TARGETS crypto
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include)

# Optionally add tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    # Enable testing
    enable_testing()
    
    # Fetch GoogleTest
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    
    # Only build gtest, not gmock
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    
    # Fetch and make Google Test available
    FetchContent_MakeAvailable(googletest)
    
    # Add the tests subdirectory
    add_subdirectory(tests)
endif()