cmake_minimum_required(VERSION 3.10)

# Set the project name
project(stm32mp-sign-tool)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(
    stm32mp-sign-tool
    src/stm32mp-sign-tool.cpp
    src/openssl-support.cpp
    src/utils.cpp
    src/stm32mp-image-signer.cpp
    src/header-manager.cpp
    src/stm32-image-format-factory.cpp
    src/stm32-image-format-mp15.cpp
)

# Headers live next to the sources
target_include_directories(stm32mp-sign-tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Link the libraries
target_link_libraries(stm32mp-sign-tool ${OPENSSL_LIBRARIES})
target_compile_options(stm32mp-sign-tool PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Specify the install rules
install(TARGETS stm32mp-sign-tool DESTINATION bin)

# Enable testing
enable_testing()
add_test(
    NAME stm32mp-sign-tool
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test/stm32mp-sign-tool_test.sh
    WORKING_DIRECTORY $<TARGET_FILE_DIR:stm32mp-sign-tool>
)
