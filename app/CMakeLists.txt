cmake_minimum_required(VERSION 3.10.2)
project(socksclient)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# 設定編譯標誌
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -latomic -O3 -fno-semantic-interposition")

# 16KB page 對齊（Android 15+ 新裝置，如小米 Pad Mini）：
# 未對齊的 .so 在 16KB page 裝置上會 dlopen 失敗（UnsatisfiedLinkError → 閃退）
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--build-id=none -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384")

set(SOURCE_FILES
    src/main/cpp/jni_bridge.c
    src/main/cpp/tun_socks.c
    src/main/cpp/checksum.c
    src/main/cpp/socks5_codec.c
    src/main/cpp/dns_synth.c
    src/main/cpp/tcp_packet.c
    src/main/cpp/ip_parse.c
    src/main/cpp/ip_hash.c
    src/main/cpp/reasm.c
    src/main/cpp/tcp_state.c
    src/main/cpp/udp_session.c
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
