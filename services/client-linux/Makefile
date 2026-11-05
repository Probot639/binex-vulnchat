# auth-client library and chat client.
#
# the library builds as a .so (linux) and .dll (windows) from one source.
# the chat client compiles auth_client.c directly in so there's no
# runtime .so dependency to deal with.
CC       ?= gcc
MINGW    ?= x86_64-w64-mingw32-gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -Iinclude
BUILD    := build

.PHONY: all linux windows client clean
all: linux client

linux: $(BUILD)/libauthclient.so
$(BUILD)/libauthclient.so: src/auth_client.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -fvisibility=hidden -shared -o $@ $<

client: $(BUILD)/chat_client
$(BUILD)/chat_client: src/chat_client.c src/auth_client.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/chat_client.c src/auth_client.c \
	  -lncurses -lpthread

windows: $(BUILD)/authclient.dll
$(BUILD)/authclient.dll: src/auth_client.c | $(BUILD)
	$(MINGW) $(CFLAGS) -shared -o $@ $< -lws2_32 \
	  -Wl,--out-implib,$(BUILD)/libauthclient.dll.a

$(BUILD): ; mkdir -p $(BUILD)
clean: ; rm -rf $(BUILD)
