# 原生 C 單元測試的統一執行入口。
#
# 用法（於 app/src/test/native 目錄，或 make -C app/src/test/native）：
#   make test          編譯並執行全部單元測試（host gcc，不需 Android/NDK）
#   make sanitize      以 ASan/UBSan 編譯並執行 offset-sensitive golden 子集
#   make fuzz          以 sanitizer 執行封包解析器 mutation fuzz（20 萬次）
#   make check-symbols 驗證抽離模組均有被 tun_socks.c 接回（防並行分叉）
#
# 新增測試：只需 (1) 補一行 SRC_<name> 宣告其額外引擎來源檔、(2) 把 <name>
# 加進 ALL_TESTS（若屬 offset-sensitive golden 測試再加 GOLDEN_TESTS）。

CC      = gcc
CFLAGS  ?= -std=c11 -Wall -Wextra
SAN     := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all
ASAN_OPTIONS := detect_leaks=0:halt_on_error=1
export ASAN_OPTIONS

MAIN := ../../main/cpp
OUT  ?= /tmp/native_tests

.DEFAULT_GOAL := test

# 每個測試額外需連結的引擎來源檔（相對 MAIN）；測試檔本身為 <name>_test.c。
SRC_checksum     := checksum.c
SRC_socks5       := socks5_codec.c
SRC_dns_synth    := dns_synth.c dns_query.c
SRC_tcp_packet   := tcp_packet.c checksum.c
SRC_ip_parse     := ip_parse.c reasm.c checksum.c
SRC_reasm        := reasm.c ip_parse.c checksum.c
SRC_ip_hash      := ip_hash.c
SRC_tcp_state    := tcp_state.c
SRC_tun_loopback := socks5_codec.c tcp_packet.c checksum.c
SRC_udp_session  := udp_session.c
SRC_fake_dns     := fake_dns.c dns_synth.c dns_query.c
SRC_dns_tcp      := dns_tcp.c
SRC_dns_query    := dns_query.c
SRC_icmp_packet  := icmp_packet.c checksum.c
SRC_udp_tcp      := udp_tcp.c
SRC_tcp_buf      := tcp_buf.c
SRC_engine_util  := engine_util.c socks5_codec.c fake_dns.c dns_synth.c dns_query.c ip_hash.c tcp_state.c
SRC_hs_pool      := hs_pool.c

# 單一測試額外的 gcc flags（如 -pthread）。
EXTRA_tun_loopback := -pthread
EXTRA_engine_util  := -D_DEFAULT_SOURCE -I . -pthread
EXTRA_hs_pool      := -D_DEFAULT_SOURCE -I . -pthread

ALL_TESTS := checksum socks5 dns_synth tcp_packet ip_parse reasm ip_hash tcp_state \
             tun_loopback udp_session fake_dns dns_tcp dns_query icmp_packet udp_tcp tcp_buf \
             engine_util hs_pool

# sanitizer 下的 golden 測試（原 CI 列舉的 offset-sensitive 子集）。
GOLDEN_TESTS := ip_parse reasm dns_synth socks5 tcp_packet fake_dns dns_tcp \
                dns_query icmp_packet udp_tcp engine_util hs_pool

# 產生每個測試的 build / run / san-build / san-run 目標。
define test_template
$(OUT)/$(1): $(1)_test.c $$(addprefix $(MAIN)/,$$(SRC_$(1)))
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(EXTRA_$(1)) -I $(MAIN) -o $$@ $(1)_test.c $$(addprefix $(MAIN)/,$$(SRC_$(1)))

run-$(1): $(OUT)/$(1)
	$$(OUT)/$(1)

$(OUT)/san-$(1): $(1)_test.c $$(addprefix $(MAIN)/,$$(SRC_$(1)))
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SAN) $(EXTRA_$(1)) -I $(MAIN) -o $$@ $(1)_test.c $$(addprefix $(MAIN)/,$$(SRC_$(1)))

san-$(1): $(OUT)/san-$(1)
	$$(OUT)/san-$(1)
endef
$(foreach t,$(ALL_TESTS),$(eval $(call test_template,$(t))))

.PHONY: test sanitize fuzz check-symbols clean tun_engine
test: $(addprefix run-,$(ALL_TESTS)) run-tun_engine
sanitize: $(addprefix san-,$(GOLDEN_TESTS)) san-tun_engine

# 封包解析器 mutation fuzz（ASan/UBSan 抓越界與未定義行為）。
FUZZ_SRC := ip_parse.c reasm.c dns_query.c dns_synth.c dns_tcp.c socks5_codec.c \
            icmp_packet.c tcp_packet.c udp_tcp.c checksum.c

$(OUT)/fuzz_parsers: fuzz_parsers.c $(addprefix $(MAIN)/,$(FUZZ_SRC))
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SAN) -I $(MAIN) -o $@ fuzz_parsers.c $(addprefix $(MAIN)/,$(FUZZ_SRC))

fuzz: $(OUT)/fuzz_parsers
	$(OUT)/fuzz_parsers 200000

# ---------------------------------------------------------------------------
# tun_engine 整合測試：連結真正的 tun_socks.c 引擎（epoll 事件迴圈 + handshake
# 執行緒 + SOCKS5 狀態機）。與純邏輯單元測試不同，需 host_jni_bridge.c（主機版
# request_java_socket）、-pthread、-I .（讓 <android/log.h> 解析到測試目錄 shim），
# 故以專用規則處理，不進入既有 test_template（其 SRC 一律以 $(MAIN) 為前綴）。
ENGINE_SRC := tun_socks.c checksum.c socks5_codec.c dns_synth.c dns_query.c \
              fake_dns.c dns_tcp.c tcp_packet.c tcp_buf.c icmp_packet.c \
              ip_parse.c ip_hash.c reasm.c tcp_state.c udp_session.c udp_tcp.c \
              engine_util.c hs_pool.c udp_sess.c tcp_sess.c

$(OUT)/tun_engine: tun_engine_test.c host_jni_bridge.c $(addprefix $(MAIN)/,$(ENGINE_SRC))
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -pthread -D_DEFAULT_SOURCE -I . -I $(MAIN) -o $@ tun_engine_test.c host_jni_bridge.c $(addprefix $(MAIN)/,$(ENGINE_SRC))

run-tun_engine: $(OUT)/tun_engine
	$(OUT)/tun_engine

# 便捷別名：`make tun_engine` 單獨編譯執行整合測試（plan 文件驗證指令即用此名）
tun_engine: run-tun_engine

$(OUT)/san-tun_engine: tun_engine_test.c host_jni_bridge.c $(addprefix $(MAIN)/,$(ENGINE_SRC))
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SAN) -pthread -D_DEFAULT_SOURCE -I . -I $(MAIN) -o $@ tun_engine_test.c host_jni_bridge.c $(addprefix $(MAIN)/,$(ENGINE_SRC))

san-tun_engine: $(OUT)/san-tun_engine
	$(OUT)/san-tun_engine

# 驗證抽離模組均有被 tun_socks.c 直接接回，避免抽離後兩者分叉。
# 僅列「tun_socks.c 直接呼叫」的第一層符號；二層輔助（如 dns_build_fake_ip6，
# 由 fake_dns.c 呼叫）不在本清單，否則 grep tun_socks.c 會誤報為分叉。
SYMBOLS := socks5_build_connect_request socks5_build_udp_frame \
           socks5_parse_udp_datagram socks5_build_hello socks5_build_auth \
           tcp_build_segment tcp_build_synack udp_build_packet \
           icmp4_build_echo_reply icmp6_build_echo_reply icmp6_build_na \
           dns_query_parse dns_build_reply_pure \
           reasm_table_insert reasm_table_gc reasm_table_clear \
           tcp_seq_gt tcp_win_field_pure tcp_parse_window_scale \
           ip_hash_bucket tcp_isn_generate tcp_win_scaled tcp_flow_window_full \
           tcp_srv_should_send_fin tcp_app_can_shutdown_write tcp_classify_in \
           tcp_is_idle tcp_post_fin_send_rst tcp_server_drained tcp_recv_full_should_close \
           tcp_buf_reserve_should_compact tcp_buf_reserve_fits tcp_buf_should_compact_half \
           tcp_buf_full tcp_buf_recv_want \
           udp_should_buffer_first_pkt udp_is_idle \
           fake_dns_alloc fake_dns_lookup fake_dns_lookup6 \
           fake_dns_find_domain fake_dns_reset fake_dns_key \
           dns_tcp_scan_frames dns_tcp_frame_len udp_tcp_consume udp_tcp_stream_init \
           socks5_classify_greet_reply socks5_auth_reply_ok socks5_atyp_bnd_len \
           ip_addr_eq \
           tcp_handle_packet tcp_handle_event tcp_flush_all tcp_sweep \
           tcp_soft_reset tcp_shutdown_collect tcp_idle_gc tcp_graveyard_collect \
           udp_handle_packet udp_handle_event udp_soft_reset udp_shutdown_collect \
           udp_idle_gc udp_graveyard_collect \
           hs_pool_start hs_pool_stop hs_submit \
           socks5_greet_auth srv_snapshot next_tcp_isn dns_build_reply \
           set_nonblocking engine_fake_dns_reset engine_srv_host_update

check-symbols:
	@fail=0; for sym in $(SYMBOLS); do n=$$(cat $(MAIN)/*.c | grep -c "\b$$sym\b" || true); if [ "$$n" -eq 0 ]; then echo "ERROR: $$sym 未在引擎原始碼中呼叫——抽離模組與引擎實作已分叉"; fail=1; fi; done; if [ "$$fail" -ne 0 ]; then exit 1; fi; echo "所有抽離模組均已接回引擎"

clean:
	rm -rf $(OUT)
