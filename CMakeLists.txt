# Specify the minimum version of CMake and define the project.
cmake_minimum_required(VERSION 3.15)
project(ProxyLab CXX)

# Set the C++ standard to C++17 (a good modern standard).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------
# FIND DEPENDENCIES
# --------------------------------------------------------------------

# Find the Boost library. We need the "system" component for Asio.
# The "REQUIRED" keyword will stop the process if Boost isn't found.
find_package(Boost REQUIRED COMPONENTS system)

# Find the OpenSSL library, which you will need for handling HTTPS.
# It's good to add this now.
find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)

find_package(ZLIB REQUIRED)


# --------------------------------------------------------------------
# DEFINE AND LINK YOUR PROGRAM
# --------------------------------------------------------------------

# Tell CMake to create an executable named "proxylab".
# It will be built from the source file at "src/main.cpp".
# (You should create a folder named "src" and put your main.cpp inside it).
add_executable(proxylab 
src/main.cpp 
src/CertificateManager.cpp 
src/EncodingUtils.cpp
)

# Link your "proxylab" executable against the libraries it needs.
# This is the crucial step that connects your code to Boost and OpenSSL.
# Add the OpenSSL include directory to your project
target_include_directories(proxylab PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link against the libraries using the variables set by the older find module
target_link_libraries(proxylab PRIVATE
    Boost::system
    ${OPENSSL_LIBRARIES}
    ZLIB::ZLIB
)
