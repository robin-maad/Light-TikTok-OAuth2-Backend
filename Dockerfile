FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production PORT=7777
EXPOSE 7777
CMD ["npm","start"]
