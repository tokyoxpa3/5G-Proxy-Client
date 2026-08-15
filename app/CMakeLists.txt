cmake_minimum_required(VERSION 3.10.2)
project(socksclient)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# 設定編譯標誌
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -latomic -O3 -fno-semantic-interposition")

set(SOURCE_FILES
    src/main/cpp/jni_bridge.c
    src/main/cpp/tun_socks.c
)

add_library(socksclient SHARED
    ${SOURCE_FILES}
)

find_library(log-lib log)

# 連結必要的庫
target_link_libraries(socksclient
    ${log-lib}
    atomic
    m
)
