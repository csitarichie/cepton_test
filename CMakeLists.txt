cmake_minimum_required(VERSION 3.1)
project(
    test_pacp_read
    VERSION 1.0.0
    LANGUAGES C CXX)

message(STATUS "Building:${CMAKE_SYSTEM_PROCESSOR}")

if (MSVC)
    set(BUILD_ARCH "x86")
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        set(BUILD_ARCH "x64")
    endif ()
endif ()

add_subdirectory(cepton_sdk_redist)

add_library(wincap::wpcap STATIC IMPORTED)
target_include_directories(wincap::wpcap INTERFACE wincap)
set_target_properties(wincap::wpcap PROPERTIES IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/wincap/winpcap_lib/${BUILD_ARCH}/wpcap.lib")

add_library(pcapp::common STATIC IMPORTED)
target_link_libraries(pcapp::common INTERFACE "Ws2_32.lib")
target_include_directories(pcapp::common INTERFACE pcapplusplus/header)
set_target_properties(pcapp::common PROPERTIES IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/pcapplusplus/${BUILD_ARCH}/${CMAKE_BUILD_TYPE}/Common++.lib")

add_library(pcapp::packet STATIC IMPORTED)
target_include_directories(pcapp::packet INTERFACE pcapplusplus/header)
set_target_properties(pcapp::packet PROPERTIES IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/pcapplusplus/${BUILD_ARCH}/${CMAKE_BUILD_TYPE}/Packet++.lib")

add_library(pcapp::pcap STATIC IMPORTED)
target_include_directories(pcapp::pcap INTERFACE pcapplusplus/header)
set_target_properties(pcapp::pcap PROPERTIES IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/pcapplusplus/${BUILD_ARCH}/${CMAKE_BUILD_TYPE}/Pcap++.lib")

add_executable(pcap_decode src/main.cpp)
target_link_libraries(pcap_decode
    cepton_sdk::cepton_sdk
    wincap::wpcap
    pcapp::common
    pcapp::packet
    pcapp::pcap
    )
set_property(TARGET pcap_decode PROPERTY CXX_STANDARD 14)

if (MSVC)
    add_custom_command(
        TARGET pcap_decode
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/cepton_sdk_redist/bin/win64
        $<TARGET_FILE_DIR:pcap_decode>)
endif ()

