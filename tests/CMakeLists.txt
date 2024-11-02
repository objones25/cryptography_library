# Add test executable
add_executable(crypto_tests
    symmetric_tests.cpp
    hash_tests.cpp
    aes_ni_tests.cpp
)

# Add include directories for tests
target_include_directories(crypto_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

# Link against Google Test and crypto library
target_link_libraries(crypto_tests
    PRIVATE
        crypto
        gtest_main
        Threads::Threads
)

# Set test output directory
set_target_properties(crypto_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

# Enable testing
include(GoogleTest)
gtest_discover_tests(crypto_tests)

# Add compiler flags for tests and enable AES-NI if available
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64)|(AMD64)|(^i.86$)")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(crypto_tests PRIVATE -maes -msse4.1)
    elseif(MSVC)
        target_compile_options(crypto_tests PRIVATE /arch:AVX2)
    endif()
endif()

# Add additional compiler warnings
target_compile_options(crypto_tests
    PRIVATE
    $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        -Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4>
)