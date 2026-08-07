#!/bin/sh
set -eu

LD_LIBRARY_PATH=/opt/postgresql/lib \
  exec /opt/postgresql/bin/psql "$@"
