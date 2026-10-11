# HARDENED build of the same app. Compare with ../insecure/Dockerfile.
FROM node:20-alpine

WORKDIR /app

# Deterministic install from the lockfile, production deps only.
# (For a real fix of the supply-chain exercise, bump the pinned versions in
#  package.json first; this image still builds the same app, hardened at the
#  container level.)
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY . .

# Create a dedicated non-root user and make the app dir owned by it. The app
# writes the Defenses-panel state to config/defenses.json, so that single path
# must stay writable (mounted as a writable volume at runtime).
RUN addgroup -S app && adduser -S -u 10001 -G app app \
    && chown -R app:app /app

USER 10001

EXPOSE 3000
ENV PORT=3000

CMD ["node", "src/server.js"]
