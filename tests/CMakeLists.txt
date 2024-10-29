include(GoogleTest)

# Add test executables
add_executable(crypto_tests
    symmetric_tests.cpp
    hash_tests.cpp
)

# Link against our library, Google Test, and Threads
target_link_libraries(crypto_tests
    PRIVATE
        crypto
        GTest::gtest
        GTest::gtest_main
        Threads::Threads
)

# Add include directories
target_include_directories(crypto_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src
)

# Enable testing with CTest
enable_testing()

# Discover tests
gtest_discover_tests(crypto_tests)