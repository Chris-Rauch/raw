cmake_minimum_required(VERSION 3.15)

project(rawlib VERSION 1.0 LANGUAGES CXX)

# c++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# find Boost and OpenSSL lib (assuming they're already installed)
find_package(Boost REQUIRED COMPONENTS json)
find_package(OpenSSL REQUIRED)

# Define the source files
file(GLOB_RECURSE RAW_SOURCES CONFIGURE_DEPENDS
    src/*.cpp
)

# Create the library target
add_library(raw STATIC ${RAW_SOURCES})

# Expose the public header interface
target_include_directories(raw
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# add specific boost interfaces here
target_link_libraries(raw PUBLIC
    Boost::json
    OpenSSL::Crypto
    OpenSSL::SSL
)
# Install the headers (flatten structure starting from include/raw/)
install(DIRECTORY include/raw
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

# Install the library
install(TARGETS raw
    EXPORT rawTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Export CMake config files
install(EXPORT rawTargets
    FILE rawTargets.cmake
    NAMESPACE raw::
    DESTINATION lib/cmake/raw
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/rawConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/rawConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rawConfig.cmake"
    INSTALL_DESTINATION lib/cmake/raw
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/rawConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/rawConfigVersion.cmake"
    DESTINATION lib/cmake/raw
)
