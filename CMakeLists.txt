# This file is part of knotdiscovery.
#
# For license and copyright information please follow this link:
# https://github.com/nelonn/knotdiscovery/blob/master/LEGAL

cmake_minimum_required(VERSION 3.15)

project(knotdiscovery LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(knotdiscovery
        include/knot/discovery.h
        src/adapter.c
        src/adapter.h
)

get_target_property(KNOTDISCOVERY_LIB_TYPE knotdiscovery TYPE)
if (KNOTDISCOVERY_LIB_TYPE STREQUAL "SHARED_LIBRARY")
    #set_target_properties(knotdiscovery PROPERTIES
    #        C_VISIBILITY_PRESET hidden
    #        CXX_VISIBILITY_PRESET hidden
    #        VISIBILITY_INLINES_HIDDEN ON
    #)

    target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_DYNAMIC)
    target_compile_definitions(knotdiscovery PUBLIC KNOTDISCOVERY_DYNAMIC_IMPORT)
endif ()

if (ANDROID)
    target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_ANDROID)
    target_sources(knotdiscovery PRIVATE src/android.c)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux" OR CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    # avahi-compat supports only service discovery, service registration is broken
    # for testing and development purposes only
    option(KNOTDISCOVERY_USE_AVAHI_COMPAT "Use avahi-compat-libdns_sd" OFF)

    #list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
    include(cmake/FindAvahi.cmake)
    target_include_directories(knotdiscovery PRIVATE ${Avahi_INCLUDE_DIRS})

    if (Avahi_FOUND AND KNOTDISCOVERY_USE_AVAHI_COMPAT)
        target_sources(knotdiscovery PRIVATE src/bonjour.c)
        target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_BONJOUR)
        target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_AVAHI_BONJOUR_COMPAT)
    else ()
        if (Avahi_FOUND)
            target_sources(knotdiscovery PRIVATE src/avahi.c)
            target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_AVAHI)
        endif ()

        target_sources(knotdiscovery PRIVATE src/mdnsh.c)
        target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_MDNSH)
    endif ()
elseif (WIN32 OR APPLE)
    target_sources(knotdiscovery PRIVATE src/bonjour.c)
    target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_BONJOUR)
    if (WIN32)
        target_sources(knotdiscovery PRIVATE src/mdnsh.c)
        target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_MDNSH)
        target_link_libraries(knotdiscovery PRIVATE ws2_32 iphlpapi)
    endif ()
elseif (ESP_PLATFORM)
    target_sources(knotdiscovery PRIVATE src/esp.c)
    target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_ESP)
else ()
    target_compile_definitions(knotdiscovery PRIVATE KNOTDISCOVERY_NOOP)
endif ()

target_include_directories(knotdiscovery PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

if (PROJECT_IS_TOP_LEVEL)
    add_subdirectory(example)
endif()
