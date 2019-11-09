# CMakeLists.txt for SmtpAuth
#
# © 2019 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This SmtpAuth)

set(Headers
    include/SmtpAuth/Client.hpp
)

set(Sources
    src/Client.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

target_link_libraries(${This} PUBLIC
    Base64
    Sasl
    Smtp
    StringExtensions
    SystemAbstractions
)

add_subdirectory(test)
