#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "No arguments supplied."
    echo "      -c|--clean          :       rebuild the authd & keygen binary"
    echo "      -s|--setup          :       setup the keys"
    echo "      -a|--auth           :       run the auth binary, the following are optional args:"
    echo "          -p|--port       :       determines the port that authd process listens on"
    echo "          -k|--key        :       sets the path to the key (filename included in path)"
    echo "          -db|--database  :       determines the directory of the database (filename included in path"
    exit 1
fi

CLEAN=false
SETUP=false
AUTH=false

PORT="4001"
KEY="keys/idp_ed25519.sk"
DIRECTORY="build/auth.db"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--clean)
      CLEAN=true
      shift
      ;;
    -s|--setup)
      SETUP=true
      shift
      ;;
    -a|--auth)
      AUTH=true
      shift
      ;;
    -p|--port)
      PORT="$2"
      shift 2
      ;;
    -k|--key)
      KEY="$2"
      shift 2
      ;;
    -d|--directory)
      DIRECTORY="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ "$CLEAN" = true ]; then
  echo "cleaning and rebuilding authd & keygen"
  make clean
  make setup
  make check
fi

if [ "$AUTH" = true ]; then
  echo "starting auth binary"
  [ -n "$PORT" ] && echo " -> Port: $PORT"
  [ -n "$KEY" ] && echo " -> Key Path: $KEY"
  [ -n "$DIRECTORY" ] && echo " -> Directory: $DIRECTORY"
  ./build/authd -p $PORT -k $KEY -d $DIRECTORY
fi

if [ "$SETUP" = true ]; then
  echo "making key"
  ./build/keygen keys
fi