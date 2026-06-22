FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
COPY apps/public-site/package*.json ./apps/public-site/
COPY apps/hub/package*.json ./apps/hub/
COPY packages/ui/package*.json ./packages/ui/
COPY packages/auth/package*.json ./packages/auth/
COPY packages/config/package*.json ./packages/config/
COPY packages/database/package*.json ./packages/database/
COPY packages/types/package*.json ./packages/types/

RUN npm ci

COPY . .

EXPOSE 3000 3001

CMD ["npm", "run", "dev"]
