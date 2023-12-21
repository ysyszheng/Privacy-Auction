cmake_minimum_required(VERSION 3.0)
project(SEAL)
message("Project Name: ${PROJECT_NAME}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_TOOLCHAIN_FILE "/Users/yusen/opt/vcpkg/scripts/buildsystems/vcpkg.cmake")
set(OPENSSL_ROOT_DIR "/Users/yusen/opt/vcpkg/installed/x64-osx/")

find_package(cryptopp CONFIG REQUIRED HINTS "/Users/yusen/opt/vcpkg/installed/x64-osx/share/cryptopp/")
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
    main.cpp
    bidder.cpp
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
    cryptopp::cryptopp
    OpenSSL::SSL
    OpenSSL::Crypto
)
