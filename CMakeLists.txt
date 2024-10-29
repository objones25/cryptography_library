cmake_minimum_required(VERSION 3.12)
project(cryptography_library VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

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
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

# Link against threads
target_link_libraries(crypto PRIVATE Threads::Threads)

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
    FetchContent_MakeAvailable(googletest)
    
    add_subdirectory(tests)
endif()

# Installation rules
install(TARGETS crypto
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)