# chat server build.
#
# the flags here are deliberate, don't "fix" them:
#   -fno-stack-protector    no canaries
#   -no-pie / -fno-pie      fixed addresses, the got.plt plan needs this
#   -z noexecstack          NX on, we're doing ROP not shellcode
#   -z relro -z lazy        partial RELRO only. full RELRO makes .got.plt
#                           read-only and kills the whole approach
#   -O0                     stops gcc inlining things we want frames for
#
# arch enables PIE+canary by default, none of this is safe to leave implicit.
# `make check` asserts the binary actually came out the way we said.

CC  := gcc
CXX := g++
BIN := chatd
BUILD := build

# shared between C and C++
WARNINGS := -Wall -Wextra
MITFLAGS := -O0 -g -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE

CFLAGS   := -std=c11 $(WARNINGS) $(MITFLAGS) -Iinclude
CXXFLAGS := -std=c++17 $(WARNINGS) $(MITFLAGS) -Iinclude
LDFLAGS  := -no-pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,lazy
LDLIBS   :=
# LDLIBS += -lsqlite3    # uncomment once db.c actually does something

# vuln code stays .c, scaffolding is .cpp
CSRC   := $(wildcard src/*.c)
CXXSRC := $(wildcard src/*.cpp)
OBJ    := $(patsubst src/%.c,$(BUILD)/%.o,$(CSRC)) \
          $(patsubst src/%.cpp,$(BUILD)/%.o,$(CXXSRC))

.PHONY: all run check clean

all: $(BUILD)/$(BIN)

# link with g++ so the c++ runtime comes in
$(BUILD)/$(BIN): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

run: all
	./$(BUILD)/$(BIN)

# make sure the mitigations are what the comment at the top claims.
# worth running before you hand the binary to anyone writing an exploit.
check: $(BUILD)/$(BIN)
	@readelf -lW $(BUILD)/$(BIN) | grep -q 'GNU_STACK.*RWE' \
	  && { echo "FAIL: executable stack"; exit 1; } || echo "ok   NX"
	@readelf -hW $(BUILD)/$(BIN) | grep -q 'Type:.*EXEC' \
	  && echo "ok   non-PIE" || { echo "FAIL: built as PIE"; exit 1; }
	@readelf -lW $(BUILD)/$(BIN) | grep -q 'GNU_RELRO' \
	  && echo "ok   RELRO segment present" || { echo "FAIL: no RELRO"; exit 1; }
	@readelf -dW $(BUILD)/$(BIN) | grep -q 'BIND_NOW' \
	  && { echo "FAIL: full RELRO, .got.plt is read-only"; exit 1; } \
	  || echo "ok   partial RELRO"
	@readelf -sW $(BUILD)/$(BIN) | grep -q '__stack_chk_fail' \
	  && { echo "FAIL: canary snuck in"; exit 1; } || echo "ok   no canary"

clean:
	rm -rf $(BUILD)
