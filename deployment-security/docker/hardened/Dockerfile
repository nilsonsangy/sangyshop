# HARDENED build of the same app. Compare with the repo's default (insecure) Dockerfile at the root.
FROM node:20-alpine

WORKDIR /app

# Bring in the full source tree first, including the root (vulnerable) manifest.
# The hardened manifest below intentionally overrides it so the image installs
# the corrected dependency versions, not the planted vulnerable ones.
COPY . .

# The hardened manifest is the last word: it overwrites the root package.json
# and lockfile copied above, so `npm ci` resolves the corrected versions.
COPY deployment-security/docker/hardened/package.json ./package.json
COPY deployment-security/docker/hardened/package-lock.json ./package-lock.json

# Deterministic install from the hardened lockfile, production deps only.
# Fail-closed: no fallback to `npm install` — if the lockfile is inconsistent,
# the build must fail instead of silently resolving different versions.
RUN rm -rf node_modules && npm ci --omit=dev

# Create a dedicated non-root user and make the app dir owned by it. The app
# writes the Defenses-panel state to config/defenses.json, so that single path
# must stay writable (mounted as a writable volume at runtime).
RUN addgroup -S app && adduser -S -u 10001 -G app app \
    && chown -R app:app /app

USER 10001

EXPOSE 3000
ENV PORT=3000

CMD ["node", "src/server.js"]
