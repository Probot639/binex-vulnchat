# windows chat server build (cross-compile from linux).
#
# mirrors the linux build's vuln flags for the same exploitation profile:
#   -fno-stack-protector    no canaries
#   -fno-pie               helps keep addresses predictable
#   -U_FORTIFY_SOURCE       no fortified libc wrappers
#   -O0                     stops gcc inlining things we want frames for
#
# PE-specific linker flags:
#   --disable-dynamicbase   disable ASLR (clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
#   --nxcompat              DEP on, we're doing ROP not shellcode
#   --no-insert-timestamp   reproducible builds
#
# `make check` asserts the binary came out the way we said.

CC  := x86_64-w64-mingw32-gcc
CXX := x86_64-w64-mingw32-g++
OBJDUMP := x86_64-w64-mingw32-objdump
BIN := chatd.exe
BUILD := build

WARNINGS := -Wall -Wextra
MITFLAGS := -O0 -g -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE

CFLAGS   := -std=c11 $(WARNINGS) $(MITFLAGS) -Iinclude
CXXFLAGS := -std=c++17 $(WARNINGS) $(MITFLAGS) -Iinclude
LDFLAGS  := -Wl,--disable-dynamicbase -Wl,--nxcompat -Wl,--no-insert-timestamp
LDLIBS   := -lws2_32
# LDLIBS += -lsqlite3    # uncomment once db actually does something

# vuln code stays .c (symlinked from chat-linux), scaffolding is .cpp
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

# verify the PE mitigations match what the comment at the top claims.
# DllCharacteristics is a bitmask in the PE optional header:
#   0x0040  DYNAMIC_BASE (ASLR)   -- should be OFF
#   0x0100  NX_COMPAT (DEP)       -- should be ON
#   0x4000  GUARD_CF (CFG)        -- should be OFF
check: $(BUILD)/$(BIN)
	@dllc=$$($(OBJDUMP) -p $(BUILD)/$(BIN) \
	  | awk '/DllCharacteristics/{print $$2}'); \
	val=$$((0x$$dllc)); \
	if [ $$((val & 0x0040)) -ne 0 ]; then \
	  echo "FAIL: ASLR enabled (DYNAMIC_BASE set)"; exit 1; \
	else echo "ok   no ASLR"; fi; \
	if [ $$((val & 0x0100)) -eq 0 ]; then \
	  echo "FAIL: DEP not enabled (NX_COMPAT not set)"; exit 1; \
	else echo "ok   DEP on"; fi; \
	if [ $$((val & 0x4000)) -ne 0 ]; then \
	  echo "FAIL: CFG enabled"; exit 1; \
	else echo "ok   no CFG"; fi

clean:
	rm -rf $(BUILD)
