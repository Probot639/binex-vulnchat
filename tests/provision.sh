#!/bin/bash
# provision.sh - install build deps and test deps inside the vagrant guest.
# runs as root during `vagrant provision`.

set -e

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# build deps for both services
apt-get install -y -qq \
    build-essential \
    gcc g++ \
    libsqlite3-dev \
    libsodium-dev \
    pkg-config \
    python3 python3-pip python3-venv \
    sqlite3 \
    gdb \
    strace \
    > /dev/null

# python test deps (system-wide, it's a throwaway VM)
pip3 install --break-system-packages pwntools 2>/dev/null || \
    pip3 install pwntools

# build both services
cd /vagrant/services/auth
make clean && make && make setup && make check

cd /vagrant/services/chat-linux
make clean && make && make check

echo ""
echo "=== provision done ==="
echo "  auth: /vagrant/services/auth/build/authd"
echo "  chat: /vagrant/services/chat-linux/build/chatd"
echo "  tests: cd /vagrant/tests && python3 -m pytest -v"
