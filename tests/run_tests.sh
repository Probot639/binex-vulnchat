#!/bin/bash
# run_tests.sh - convenience wrapper for the test suite.
#
# usage:
#   ./run_tests.sh                       # run all tests (local servers)
#   ./run_tests.sh auth                  # auth tests only
#   ./run_tests.sh chat                  # chat-linux tests only
#   ./run_tests.sh exploits              # exploit validation only
#   ./run_tests.sh win                   # windows chat tests via wine
#   ./run_tests.sh win HOST PORT         # windows chat tests against remote
#   ./run_tests.sh all-remote HOST PORT  # all tests against remote chat server

cd "$(dirname "$0")"

case "${1:-all}" in
    auth)
        python3 -m pytest test_auth_functional.py -v
        ;;
    chat)
        python3 -m pytest test_chat_functional.py -v
        ;;
    exploits)
        python3 -m pytest test_exploits.py -v
        ;;
    exploits-win)
        python3 -m pytest test_exploits_win.py -v -p no:timeout
        ;;
    win)
        if [ -n "$2" ]; then
            HOST="$2"; PORT="${3:-4002}"
            python3 -m pytest test_chat_win.py test_exploits_win.py -v -p no:timeout \
                --chat-host="$HOST" --chat-port="$PORT"
        else
            python3 -m pytest test_chat_win.py test_exploits_win.py -v -p no:timeout
        fi
        ;;
    all-remote)
        HOST="${2:?need HOST}"; PORT="${3:-4002}"
        python3 -m pytest -v -p no:timeout --chat-host="$HOST" --chat-port="$PORT"
        ;;
    all)
        python3 -m pytest -v -p no:timeout
        ;;
    *)
        echo "usage: $0 {all|auth|chat|exploits|exploits-win|win [HOST [PORT]]|all-remote HOST [PORT]}"
        exit 1
        ;;
esac
