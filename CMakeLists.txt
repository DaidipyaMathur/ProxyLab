# Specify the minimum version of CMake and define the project.
cmake_minimum_required(VERSION 3.15)
project(ProxyLab CXX)

# Set the C++ standard to C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------
# FIND DEPENDENCIES
# --------------------------------------------------------------------

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)

# --- THE KEY FIX ---
# Explicitly tell pkg-config where to find the sqlcipher.pc file.
# This avoids the need for the 'export' command in the terminal.
set(ENV{PKG_CONFIG_PATH} "/usr/lib/x86_64-linux-gnu/pkgconfig")
pkg_search_module(SQLCIPHER REQUIRED sqlcipher)
# --- END FIX ---

# --------------------------------------------------------------------
# DEFINE AND LINK YOUR PROGRAM
# --------------------------------------------------------------------

add_executable(proxylab 
    src/main.cpp 
    src/CertificateManager.cpp 
    src/EncodingUtils.cpp
    src/DatabaseManager.cpp
)

# Use target_include_directories for includes from found packages.
target_include_directories(proxylab PRIVATE 
    ${SQLCIPHER_INCLUDE_DIRS}
)

# Link against the modern imported targets and found libraries.
target_link_libraries(proxylab PRIVATE
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${SQLCIPHER_LIBRARIES} # Use the variable from pkg_search_module
)
