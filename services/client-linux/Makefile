# auth-client library: Linux .so + Windows .dll from one source.
CC       ?= gcc
MINGW    ?= x86_64-w64-mingw32-gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -Iinclude
BUILD    := build

.PHONY: all linux windows clean
all: linux windows

linux: $(BUILD)/libauthclient.so
$(BUILD)/libauthclient.so: src/auth_client.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -fvisibility=hidden -shared -o $@ $<

windows: $(BUILD)/authclient.dll
$(BUILD)/authclient.dll: src/auth_client.c | $(BUILD)
	$(MINGW) $(CFLAGS) -shared -o $@ $< -lws2_32 \
	  -Wl,--out-implib,$(BUILD)/libauthclient.dll.a

$(BUILD): ; mkdir -p $(BUILD)
clean: ; rm -rf $(BUILD)