# HARDENED build of the same app. Compare with the repo's default (insecure) Dockerfile at the root.
FROM node:20-alpine

WORKDIR /app

# Bring in the full source tree first, including the root (vulnerable) manifest.
# The hardened manifest below intentionally overrides it so the image installs
# the corrected dependency versions, not the planted vulnerable ones.
COPY . .

# The hardened manifest is the last word: it overwrites the root package.json
# and lockfile copied above, so `npm ci` resolves the corrected versions. It
# also pins the PostgreSQL driver `pg` at the same exact version as the root
# manifest (8.23.1), so the Postgres client is present in the image and the app
# can open the connection using the DB_Secret described below.
COPY ops/docker/hardened/package.json ./package.json
COPY ops/docker/hardened/package-lock.json ./package-lock.json

# Deterministic install from the hardened lockfile, production deps only.
# Installs `pg` (the PostgreSQL driver) among the corrected dependencies.
# Fail-closed: no fallback to `npm install` — if the lockfile is inconsistent,
# the build must fail instead of silently resolving different versions.
RUN rm -rf node_modules && npm ci --omit=dev

# Create a dedicated non-root user and make the app dir owned by it. The app
# writes the Defenses-panel state to config/defenses.json, so that single path
# must stay writable (mounted as a writable volume at runtime).
RUN addgroup -S app && adduser -S -u 10001 -G app app \
    && chown -R app:app /app

# App-owned secret directory. On most targets the hardened app reads the DB
# password from /run/secrets/db_password, but on AWS ECS Fargate the ephemeral
# /run/secrets volume is mounted as root while the container runs as UID 10001,
# so the non-root user cannot write there. This directory is owned by the app
# user, so when DB_PASSWORD_FILE points at it (Fargate) the entrypoint wrapper
# can write/read the secret file without root. It is unused otherwise.
RUN mkdir -p /app/secrets && chown -R app:app /app/secrets

USER 10001

EXPOSE 3000
ENV PORT=3000

# Runtime wiring (see docker-compose.yml): the app runs in hardened mode
# (APP_MODE=hardened, DB_BACKEND=pg) and reads the PostgreSQL password from the
# Docker secret mounted at /run/secrets/db_password — never from a plaintext
# env var or hardcoded value (R5.1/R5.2/R9.4). The secret is provided
# out-of-band at run time and is not baked into this image.
CMD ["node", "src/server.js"]
