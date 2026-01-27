cmake_minimum_required (VERSION 3.21)

project (mtls-tun)

configure_file(${PROJECT_SOURCE_DIR}/config/ca.pem          ${CMAKE_CURRENT_BINARY_DIR}/ca.pem COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/config/client-cert.pem ${CMAKE_CURRENT_BINARY_DIR}/client-cert.pem COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/config/client-key.pem  ${CMAKE_CURRENT_BINARY_DIR}/client-key.pem COPYONLY)

if(WIN32)
    set(OPENSSL_USE_STATIC_LIBS     TRUE)
    set(OPENSSL_MSVC_STATIC_RT      TRUE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_VS_JUST_MY_CODE_DEBUGGING "$<$<CONFIG:Debug>:ON>")
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL path:           ${OPENSSL_ROOT_DIR}")
    message(STATUS "OpenSSL include path:   ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries path: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL "OpenSSL Not Found")
endif()

include(FetchContent)

FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-36-0
)
FetchContent_MakeAvailable(asio)

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)

FetchContent_Declare(cliap
    GIT_REPOSITORY https://github.com/almageir/cliap.git
    GIT_TAG        master
)
option(CLIAP_STANDALONE_BUILD off)
FetchContent_MakeAvailable(cliap)


option(ASIOXX_BUILD_EXAMPLES "Build examples" OFF)
add_subdirectory(libs/asioxx)

add_executable(mtls-tun)
target_sources(mtls-tun
    PRIVATE
        src/main.cpp
        src/app/server.cpp
        src/app/session.cpp
        src/app/server.h
        src/app/session.h
        src/app/manager.h
)

target_link_libraries(mtls-tun
        PRIVATE
            asio
            cliap::cliap
            OpenSSL::SSL
            OpenSSL::Crypto
            asynclog::asynclog
)

target_compile_features(mtls-tun PRIVATE cxx_std_20)
target_compile_definitions(mtls-tun PRIVATE "_WIN32_WINNT=0x0A00")
