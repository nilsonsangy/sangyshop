# INSECURE ON PURPOSE - teaching baseline. Do NOT copy this into production.
# Mirrors the default build, but makes the loose posture explicit for comparison
# against ../hardened/Dockerfile.
FROM node:20-alpine

WORKDIR /app

# Dependencies include intentionally outdated packages (the supply-chain exercise):
# lodash 4.17.11, minimist 1.2.0, marked 0.3.6 carry known CVEs on purpose.
COPY package.json ./
RUN npm install --omit=dev || npm install

COPY . .

EXPOSE 3000
ENV PORT=3000

# No USER instruction: the process runs as root (uid 0) - a deliberate weakness.
CMD ["node", "src/server.js"]
