# SangyShop - lightweight image for the OWASP Top 10:2025 lab (defensive perspective)
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
