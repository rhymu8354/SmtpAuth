# CMakeLists.txt for SmtpAuthTests
#
# © 2019 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This SmtpAuthTests)

set(Sources
    src/ClientTests.cpp
)

add_executable(${This} ${Sources})
set_target_properties(${This} PROPERTIES
    FOLDER Tests
)

target_include_directories(${This} PRIVATE ..)

target_link_libraries(${This} PUBLIC
    gtest_main
    Sasl
    SmtpAuth
    SystemAbstractions
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
