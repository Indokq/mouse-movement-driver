cmake_minimum_required(VERSION 3.15)
project(NeacMapLoader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.cpp
    NeacInterface.cpp
    Mapper.cpp
)

set(HEADERS
    NeacInterface.hpp
    Mapper.hpp
)

# Executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    fltLib
    advapi32
)

# Compiler flags
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
        /WX-
        /arch:SSE2
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        _UNICODE
        UNICODE
        WIN32_LEAN_AND_MEAN
    )
endif()

# Output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
