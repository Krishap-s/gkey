#!/bin/sh
# Run the gkey test suite.
#
# Copyright (C) 2026 Krishap <krishapbusiness@gmail.com>
#
# This file is part of gkey.
#
# gkey is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# When swtpm is installed, a temporary software TPM is started so that
# the tests that need a TPM run as well.  When python-fido2 1.x is
# installed too, a third party FIDO2 client and relying party exercise
# the authenticator over CTAPHID.

set -e

: "${CARGO:=cargo}"
: "${PYTHON3:=python3}"
: "${srcdir:=.}"
: "${CARGO_TARGET_DIR:=$srcdir/target}"
export CARGO_TARGET_DIR

manifest="$srcdir/Cargo.toml"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gkey-check.XXXXXX")
swtpm_pid=
server_pid=

cleanup () {
  if test -n "$server_pid"; then kill "$server_pid" 2>/dev/null || :; fi
  if test -n "$swtpm_pid"; then kill "$swtpm_pid" 2>/dev/null || :; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

if command -v swtpm > /dev/null 2>&1; then
  port=$(( $$ % 20000 + 20000 ))
  mkdir "$tmp/tpm"
  swtpm socket --tpm2 --tpmstate dir="$tmp/tpm" \
    --server type=tcp,port="$port" --ctrl type=tcp,port=$((port + 1)) \
    --flags not-need-init,startup-clear --pid file="$tmp/swtpm.pid" --daemon
  swtpm_pid=$(cat "$tmp/swtpm.pid")
  GKEY_TEST_TCTI="swtpm:host=127.0.0.1,port=$port"
  export GKEY_TEST_TCTI
else
  echo "run-tests.sh: swtpm not found; skipping the tests that need a TPM" >&2
fi

# Build in the release profile, like the programs, to reuse their
# dependencies.
"$CARGO" test --release --manifest-path "$manifest" $CARGOFLAGS

if test -n "$swtpm_pid" \
   && "$PYTHON3" -c 'import fido2, sys; sys.exit(fido2.__version__[0] != "1")' 2>/dev/null
then
  "$CARGO" build --release --manifest-path "$manifest" $CARGOFLAGS \
    --example socket-authenticator
  GKEY_TCTI=$GKEY_TEST_TCTI "$CARGO_TARGET_DIR/release/examples/socket-authenticator" \
    "$tmp/socket" "$tmp/keystore" &
  server_pid=$!
  tries=0
  while test ! -S "$tmp/socket"; do
    tries=$((tries + 1))
    if test $tries -gt 100; then
      echo "run-tests.sh: socket-authenticator did not start" >&2
      exit 1
    fi
    sleep 0.1
  done
  "$PYTHON3" "$srcdir/tests/fido2-client.py" "$tmp/socket"
  kill "$server_pid"
  wait "$server_pid" || :
  server_pid=
else
  echo "run-tests.sh: swtpm or python-fido2 1.x missing; skipping the client test" >&2
fi
