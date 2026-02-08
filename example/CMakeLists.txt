cmake_minimum_required(VERSION 3.15)

project(knotdiscovery_example LANGUAGES C CXX)

add_executable(knotdiscovery_example main.cpp)
target_link_libraries(knotdiscovery_example PRIVATE knotdiscovery)
if (WIN32)
    target_link_libraries(knotdiscovery_example PRIVATE ws2_32)
endif ()
