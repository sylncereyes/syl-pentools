#!/usr/bin/env bash
TOKEN_FILE=qa/auth/b_token exec bash "$(dirname "$0")/api.sh" "$@"
