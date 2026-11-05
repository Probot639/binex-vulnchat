# auth-client library and chat client (windows cross-compile).
CC       ?= gcc
MINGW    ?= x86_64-w64-mingw32-gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -Iinclude
BUILD    := build

.PHONY: all linux windows client clean
all: linux windows client

linux: $(BUILD)/libauthclient.so
$(BUILD)/libauthclient.so: src/auth_client.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -fvisibility=hidden -shared -o $@ $<

windows: $(BUILD)/authclient.dll
$(BUILD)/authclient.dll: src/auth_client.c | $(BUILD)
	$(MINGW) $(CFLAGS) -shared -o $@ $< -lws2_32 \
	  -Wl,--out-implib,$(BUILD)/libauthclient.dll.a

client: $(BUILD)/chat_client.exe
$(BUILD)/chat_client.exe: src/chat_client.c src/auth_client.c | $(BUILD)
	$(MINGW) $(CFLAGS) -o $@ src/chat_client.c src/auth_client.c -lws2_32

$(BUILD): ; mkdir -p $(BUILD)
clean: ; rm -rf $(BUILD)
