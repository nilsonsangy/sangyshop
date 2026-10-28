#!/bin/sh
# secret-entrypoint.sh — ECS Fargate secret->file entrypoint wrapper for the
# HARDENED SangyShop image (multi-cloud-deploy, task 9.1).
#
# WHY THIS EXISTS
# ---------------
# The hardened app (src/db/credentials.js, hardened mode) reads the PostgreSQL
# password EXCLUSIVELY from the file /run/secrets/db_password and fail-closes on
# a missing/empty file. It deliberately refuses to read the password from the
# environment. See the fail-closed contract in src/db/credentials.js.
#
# AWS ECS Fargate, however, injects Secrets Manager values as ENVIRONMENT
# VARIABLES, not as mounted files (unlike GCP Cloud Run and Azure ACI, which
# mount the secret as a file natively and need no wrapper). This thin wrapper
# bridges that gap WITHOUT modifying the app image or app code: the ECS task
# definition sets its container `command` (or entrypoint) to run this wrapper,
# which:
#   1. reads the injected secret env var (DB_PASSWORD_SECRET),
#   2. writes its value — with ALL leading/trailing whitespace removed — to
#      /run/secrets/db_password  (Requirement 3.5 / 3.1),
#   3. unsets DB_PASSWORD_SECRET so the secret no longer lives in the app's
#      environment (Requirement 3.5),
#   4. exec's `node src/server.js` so the app becomes PID 1's successor and
#      receives signals correctly.
#
# /run/secrets MUST be a writable ephemeral path. The container runs as a
# non-root user (UID 10001, see the hardened Dockerfile), so the ECS task
# definition provides /run/secrets as a writable tmpfs/ephemeral mount (see
# README.md in this folder). This script creates the directory if absent.
#
# This script intentionally uses only POSIX sh features so it runs under the
# BusyBox `sh` present in the node:20-alpine hardened image. It is referenced by
# the task definition authored in task 9.2 (aws/docker/deploy.ps1); it is never
# baked into the app image and never changes the image's default CMD.
#
# SECURITY NOTES
# --------------
# - The secret value is NEVER printed. `set -x` is never enabled, and the value
#   is only ever assigned/redirected, not echoed.
# - The secret file is created with restrictive permissions (owner read/write
#   only) via umask before the write and an explicit chmod after it.
# - The env var holding the secret is unset before the app starts, so the app's
#   process environment does not carry DB_PASSWORD_SECRET (or any DB_PASSWORD).

set -eu

# Name of the env var ECS injects from Secrets Manager. Overridable so the task
# definition can pick a different secret key name if ever needed, but defaults
# to the name used by the deploy script (task 9.2).
SECRET_ENV_NAME="${SECRET_ENV_NAME:-DB_PASSWORD_SECRET}"

# Target file + directory consumed by the hardened app.
SECRET_DIR="/run/secrets"
SECRET_FILE="${SECRET_DIR}/db_password"

# Resolve the injected secret value by indirect expansion of SECRET_ENV_NAME.
# Using eval on a name we control (not on the secret value) keeps POSIX sh
# compatibility. Fail closed if the variable is unset or empty.
secret_value="$(eval "printf '%s' \"\${${SECRET_ENV_NAME}:-}\"")"
if [ -z "${secret_value}" ]; then
  # No value and no var surface the secret, so emit a non-secret error and stop
  # before launching the app (Requirement 3.4: fail without leaking the value).
  echo "secret-entrypoint: ${SECRET_ENV_NAME} is unset or empty; refusing to start (hardened mode needs ${SECRET_FILE})" >&2
  exit 1
fi

# Trim ALL leading and trailing whitespace (spaces, tabs, CR, LF). This mirrors
# the .trim() the hardened credentials module applies, and satisfies Requirement
# 3.1/3.5 ("plain file content with all leading and trailing whitespace
# removed"). We strip at both ends one char at a time using POSIX parameter
# expansion so no external tool (sed/awk) is required.
#
# ws holds the whitespace characters to strip: space, tab, carriage return,
# newline. It is built with printf so the bytes are exact and the script source
# contains no literal control characters.
ws="$(printf ' \t\r\n_')"; ws="${ws%_}"   # trailing _ guards the $() newline strip

# Strip leading whitespace, one character at a time.
while [ -n "${secret_value}" ]; do
  first="${secret_value%"${secret_value#?}"}"   # the first character
  case "${ws}" in
    *"${first}"*) secret_value="${secret_value#?}" ;;
    *) break ;;
  esac
done
# Strip trailing whitespace, one character at a time.
while [ -n "${secret_value}" ]; do
  last="${secret_value#"${secret_value%?}"}"     # the last character
  case "${ws}" in
    *"${last}"*) secret_value="${secret_value%?}" ;;
    *) break ;;
  esac
done

if [ -z "${secret_value}" ]; then
  echo "secret-entrypoint: ${SECRET_ENV_NAME} is only whitespace; refusing to start" >&2
  exit 1
fi

# Ensure the writable ephemeral directory exists, then write the trimmed value
# with restrictive permissions. umask 077 makes the freshly created file
# owner-only; chmod re-asserts it in case the file already existed.
mkdir -p "${SECRET_DIR}"
( umask 077; printf '%s' "${secret_value}" > "${SECRET_FILE}" )
chmod 600 "${SECRET_FILE}" 2>/dev/null || true

# Drop the secret from the environment so the launched app never sees it.
unset secret_value
unset "${SECRET_ENV_NAME}"

# Hand off to the application as the final process so it receives signals.
exec node src/server.js
