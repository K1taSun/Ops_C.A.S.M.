cmake_minimum_required(VERSION 3.20)

project(CASM VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" ON)

if(NOT WIN32)
    message(WARNING "This project is Windows-only")
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /MP)
    add_definitions(-DUNICODE -D_UNICODE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# core lib
set(CORE_SRC
    core/src/process_manager.cpp
    core/src/process_hider.cpp
    core/src/system_info.cpp
    core/src/casm_api.cpp
)

add_library(casm_core SHARED ${CORE_SRC})
target_include_directories(casm_core PUBLIC core/include)
target_compile_definitions(casm_core PRIVATE CASM_EXPORTS)

if(WIN32)
    target_link_libraries(casm_core PRIVATE psapi pdh ntdll)
endif()

# static lib
add_library(casm_static STATIC ${CORE_SRC})
target_include_directories(casm_static PUBLIC core/include)
if(WIN32)
    target_link_libraries(casm_static PRIVATE psapi pdh ntdll)
endif()

# tests
if(BUILD_TESTS)
    enable_testing()
    
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )
        FetchContent_MakeAvailable(googletest)
    endif()
    
    add_executable(tests
        tests/core/test_process_manager.cpp
        tests/core/test_system_info.cpp
    )
    target_link_libraries(tests PRIVATE casm_static GTest::gtest GTest::gtest_main)
    
    include(GoogleTest)
    gtest_discover_tests(tests)
endif()

# install
install(TARGETS casm_core casm_static
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(DIRECTORY core/include/ DESTINATION include/casm)

message(STATUS "C.A.S.M. v${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
