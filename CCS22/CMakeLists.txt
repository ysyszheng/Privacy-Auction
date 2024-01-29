cmake_minimum_required(VERSION 3.14)
project(CCS22)
message("Project Name: ${PROJECT_NAME}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wextra")
set(VCPKG_ROOT "/Users/yusen/opt/vcpkg")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
set(OPENSSL_ROOT_DIR "${VCPKG_ROOT}/installed/x64-osx/")

find_package(cryptopp CONFIG REQUIRED HINTS "${VCPKG_ROOT}/installed/x64-osx/share/cryptopp/")
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
    main.cpp
    bidder.cpp
    bulletinBoard.cpp
    hash.cpp
    evaluator.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
    cryptopp::cryptopp
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
