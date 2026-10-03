# SangyShop - imagem leve para o laboratorio do OWASP Top 10:2025 (visao de defesa)
FROM node:20-alpine

WORKDIR /app

# Instala dependencias (inclui as desatualizadas de proposito p/ o exercicio A03)
COPY package.json ./
RUN npm install --omit=dev || npm install

# Copia o restante do app
COPY . .

EXPOSE 3000
ENV PORT=3000

CMD ["node", "src/server.js"]
