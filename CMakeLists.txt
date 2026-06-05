cmake_minimum_required(VERSION 3.28)
project(rsa_step_by_step)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(rsa_lib
        src/bigint/bigint.cpp
        src/rsa/rsa_key.cpp
        src/rsa/rsa_engine.cpp
)

target_include_directories(rsa_lib PUBLIC include)

target_link_libraries(rsa_lib OpenSSL::Crypto)

add_executable(rsa
        src/main.cpp
)

target_link_libraries(rsa rsa_lib)

add_executable(test_rsa
        tests/test_rsa.cpp
)

target_link_libraries(test_rsa rsa_lib)

