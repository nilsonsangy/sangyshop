# SangyShop - lightweight image for the OWASP Top 10:2025 lab (defensive perspective)
# This is the DEFAULT, INSECURE (vulnerable) baseline: it runs as root, keeps the
# intentionally outdated dependencies, and applies no container hardening. It is the
# image produced by `docker compose up -d --build` and tagged `sangyshop:insecure`.
# For the hardened counterpart, see deployment-security/docker/hardened/Dockerfile.
FROM node:20-alpine

WORKDIR /app

# Install dependencies (includes the intentionally outdated ones for the A03 exercise)
COPY package.json ./
RUN npm install --omit=dev || npm install

# Copy the rest of the app
COPY . .

EXPOSE 3000
ENV PORT=3000

CMD ["node", "src/server.js"]
