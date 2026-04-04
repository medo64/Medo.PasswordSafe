#!/bin/bash
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

wget https://github.com/pwsafe/pwsafe/raw/refs/heads/master/docs/formatV3.txt -O "$SCRIPT_DIR/../resources/formatV3.txt"
