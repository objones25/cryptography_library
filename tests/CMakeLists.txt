# tests/CMakeLists.txt
include(GoogleTest)

# Add test executable
add_executable(symmetric_tests
    symmetric_tests.cpp
)

# Link against Google Test and our crypto library
target_link_libraries(symmetric_tests
    PRIVATE
        crypto
        GTest::gtest
        GTest::gtest_main
)

# Add include directories from the crypto library
get_target_property(CRYPTO_INCLUDES crypto INCLUDE_DIRECTORIES)
target_include_directories(symmetric_tests
    PRIVATE
        ${CRYPTO_INCLUDES}
        ${PROJECT_SOURCE_DIR}/include
)

# Enable testing
enable_testing()

# Discover tests
gtest_discover_tests(symmetric_tests)