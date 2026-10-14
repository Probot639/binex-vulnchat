# auth server (IdP): framed TCP, Ed25519 JWTs, sqlite store, intentional vuln.
#
# Mitigation flags match chat-linux and are deliberate -- don't "fix" them:
#   -fno-stack-protector   no canaries
#   -fno-pie / -no-pie     fixed .text/.plt/.got.plt (leak only the stack)
#   -U_FORTIFY_SOURCE      keep memcpy a real memcpy (fortify would add
#                          __memcpy_chk and turn the overflow into an abort)
#   -z noexecstack         NX on -> forces the mprotect ROP
#   -z relro -z lazy       partial RELRO; full RELRO makes .got.plt read-only
#   -O0                    simple fixed frames, no inlining of the vuln
CC  := gcc
CXX := g++
BUILD := build

WARN     := -Wall -Wextra
MIT      := -O0 -g -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE
CFLAGS   := -std=c11   $(WARN) $(MIT) -Iinclude $(shell pkg-config --cflags libsodium)
CXXFLAGS := -std=c++17 $(WARN) $(MIT) -Iinclude $(shell pkg-config --cflags libsodium sqlite3)
LDFLAGS  := -no-pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,lazy
LDLIBS   := -lsqlite3 $(shell pkg-config --libs libsodium)

# vuln + helpers stay .c; sqlite scaffolding is .cpp
ADUOBJ := $(BUILD)/db.o
SRVOBJ := $(BUILD)/main.o $(BUILD)/net.o $(BUILD)/auth_login.o \
          $(BUILD)/token.o $(BUILD)/b64url.o $(ADUOBJ)
KEYOBJ := $(BUILD)/keygen.o $(ADUOBJ)

.PHONY: all setup check clean
all: $(BUILD)/authd $(BUILD)/keygen

$(BUILD)/authd: $(SRVOBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)      # link with g++ for db.cpp

$(BUILD)/keygen: $(KEYOBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c   | $(BUILD) ; $(CC)  $(CFLAGS)   -c -o $@ $<
$(BUILD)/%.o: src/%.cpp | $(BUILD) ; $(CXX) $(CXXFLAGS) -c -o $@ $<
$(BUILD): ; mkdir -p $(BUILD)

# lab setup: signing keypair + seeded user in the sqlite db
setup: all
	./$(BUILD)/keygen keys
	./$(BUILD)/keygen adduser alice password123 $(BUILD)/auth.db
	@echo "seeded $(BUILD)/auth.db with alice/password123"

# assert the binary came out exploitable (same checks as chat-linux)
check: $(BUILD)/authd
	@readelf -lW $(BUILD)/authd | grep -q 'GNU_STACK.*RWE' \
	  && { echo "FAIL: exec stack"; exit 1; } || echo "ok   NX"
	@readelf -hW $(BUILD)/authd | grep -q 'Type:.*EXEC' \
	  && echo "ok   non-PIE" || { echo "FAIL: PIE"; exit 1; }
	@readelf -lW $(BUILD)/authd | grep -q 'GNU_RELRO' \
	  && echo "ok   RELRO segment" || { echo "FAIL: no RELRO"; exit 1; }
	@readelf -dW $(BUILD)/authd | grep -q 'BIND_NOW' \
	  && { echo "FAIL: full RELRO"; exit 1; } || echo "ok   partial RELRO"
	@readelf -sW $(BUILD)/authd | grep -q '__stack_chk_fail' \
	  && { echo "FAIL: canary"; exit 1; } || echo "ok   no canary"

clean: ; rm -rf $(BUILD)