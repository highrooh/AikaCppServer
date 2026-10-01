cmake_minimum_required(VERSION 3.24)

project(AikaCpp LANGUAGES CXX)

set(AIKA_RUNTIME_ASSET_ROOT "" CACHE PATH
    "Directory containing AikaServer.ini, SL.bin, and the server Data directory")
if(AIKA_RUNTIME_ASSET_ROOT STREQUAL "")
    set(_aika_default_asset_root
        "${CMAKE_CURRENT_SOURCE_DIR}/../Aika Lore Community/Server/Bin")
    if(EXISTS "${_aika_default_asset_root}/AikaServer.ini" AND
       EXISTS "${_aika_default_asset_root}/SL.bin" AND
       IS_DIRECTORY "${_aika_default_asset_root}/Data")
        set(AIKA_RUNTIME_ASSET_ROOT "${_aika_default_asset_root}")
    endif()
endif()

set(AIKA_NPC_ASSET_ROOT "C:/Database/NPCs" CACHE PATH
    "Directory containing the server NPC definition files")

add_library(aika_protocol STATIC
    src/protocol/crypto.cpp
    src/protocol/frame_decoder.cpp
    src/protocol/packet_header.cpp
)

add_library(aika_config STATIC
    src/config/runtime_layout.cpp
    src/config/server_config.cpp
)

add_library(aika_data STATIC
    src/data/game_tables.cpp
    src/data/server_list.cpp
    src/data/world_data.cpp
)

set(MYSQL_ROOT "C:/Program Files/MySQL/MySQL Server 8.0" CACHE PATH
    "MySQL Server installation used for the C client library")
find_path(MYSQL_INCLUDE_DIR mysql.h PATHS "${MYSQL_ROOT}/include" NO_DEFAULT_PATH REQUIRED)
find_library(MYSQL_CLIENT_LIBRARY NAMES libmysql mysqlclient
    PATHS "${MYSQL_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(aika_database STATIC src/database/mysql_connection.cpp)
target_include_directories(aika_database PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE "${MYSQL_INCLUDE_DIR}")
target_compile_features(aika_database PUBLIC cxx_std_20)
target_link_libraries(aika_database PUBLIC "${MYSQL_CLIENT_LIBRARY}")

add_executable(aika_server
    src/auth/account_auth.cpp
    src/network/tcp_listener.cpp
    src/server/auth_listeners.cpp
    src/server/game_channels.cpp
    src/server/main.cpp
)
target_link_libraries(aika_server PRIVATE
    aika_protocol aika_config aika_data aika_database bcrypt ws2_32)
target_compile_features(aika_server PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(aika_database PRIVATE /W4 /permissive- /Zc:__cplusplus)
    target_compile_options(aika_server PRIVATE /W4 /permissive- /Zc:__cplusplus)
    add_custom_command(TARGET aika_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MYSQL_ROOT}/lib/libmysql.dll"
            "$<TARGET_FILE_DIR:aika_server>/libmysql.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MYSQL_ROOT}/bin/libssl-3-x64.dll"
            "$<TARGET_FILE_DIR:aika_server>/libssl-3-x64.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MYSQL_ROOT}/bin/libcrypto-3-x64.dll"
            "$<TARGET_FILE_DIR:aika_server>/libcrypto-3-x64.dll")

    if(AIKA_RUNTIME_ASSET_ROOT AND
       EXISTS "${AIKA_RUNTIME_ASSET_ROOT}/AikaServer.ini" AND
       EXISTS "${AIKA_RUNTIME_ASSET_ROOT}/SL.bin" AND
       IS_DIRECTORY "${AIKA_RUNTIME_ASSET_ROOT}/Data")
        add_custom_command(TARGET aika_server POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIKA_RUNTIME_ASSET_ROOT}/AikaServer.ini"
                "$<TARGET_FILE_DIR:aika_server>/AikaServer.ini"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${AIKA_RUNTIME_ASSET_ROOT}/SL.bin"
                "$<TARGET_FILE_DIR:aika_server>/SL.bin"
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${AIKA_RUNTIME_ASSET_ROOT}/Data"
                "$<TARGET_FILE_DIR:aika_server>/Data"
            COMMENT "Packaging Aika server runtime data beside aika_server.exe")
    else()
        message(FATAL_ERROR
            "Aika runtime assets were not found. Set AIKA_RUNTIME_ASSET_ROOT to "
            "the directory containing AikaServer.ini, SL.bin, and Data; "
            "the server will not run without those assets.")
    endif()

    if(NOT IS_DIRECTORY "${AIKA_NPC_ASSET_ROOT}")
        message(FATAL_ERROR
            "NPC definitions were not found. Set AIKA_NPC_ASSET_ROOT to the "
            "directory containing the .npc records.")
    endif()
    file(GLOB _aika_npc_files CONFIGURE_DEPENDS
        "${AIKA_NPC_ASSET_ROOT}/*.npc")
    if(NOT _aika_npc_files)
        message(FATAL_ERROR
            "AIKA_NPC_ASSET_ROOT contains no .npc records: ${AIKA_NPC_ASSET_ROOT}")
    endif()
    add_custom_command(TARGET aika_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${AIKA_NPC_ASSET_ROOT}"
            "$<TARGET_FILE_DIR:aika_server>/NPCs"
        COMMENT "Packaging NPC definitions beside aika_server.exe")
endif()

target_include_directories(aika_protocol
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(aika_protocol PUBLIC cxx_std_20)
target_compile_features(aika_config PUBLIC cxx_std_20)
target_compile_features(aika_data PUBLIC cxx_std_20)

target_include_directories(aika_config
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_include_directories(aika_data
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(MSVC)
    target_compile_options(aika_protocol PRIVATE /W4 /permissive- /Zc:__cplusplus)
    target_compile_options(aika_config PRIVATE /W4 /permissive- /Zc:__cplusplus)
    target_compile_options(aika_data PRIVATE /W4 /permissive- /Zc:__cplusplus)
else()
    target_compile_options(aika_protocol PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    target_compile_options(aika_config PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    target_compile_options(aika_data PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()
