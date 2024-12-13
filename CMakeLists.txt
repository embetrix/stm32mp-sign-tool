cmake_minimum_required(VERSION 3.10)

# Set the project name
project(stm32mp-sign-tool)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(stm32mp-sign-tool stm32mp-sign-tool.cpp)

# Link the libraries
target_link_libraries(stm32mp-sign-tool ${OPENSSL_LIBRARIES})
target_compile_options(stm32mp-sign-tool PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror -Wno-deprecated-declarations)

# Specify the install rules
install(TARGETS stm32mp-sign-tool DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME stm32mp-sign-tool COMMAND ./stm32mp-sign-test.sh)
