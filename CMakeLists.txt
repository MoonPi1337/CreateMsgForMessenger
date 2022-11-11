cmake_minimum_required(VERSION 3.10)

project(CreateMsgForMessenger)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)


include_directories(include)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
