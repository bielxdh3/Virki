FROM node:22-alpine

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

COPY package*.json ./
COPY apps/public-site/package*.json ./apps/public-site/
COPY apps/hub/package*.json ./apps/hub/
COPY apps/issuer/package*.json ./apps/issuer/
COPY packages/auth/package*.json ./packages/auth/
COPY packages/database/package*.json ./packages/database/
COPY packages/database/prisma ./packages/database/prisma
COPY packages/database/scripts ./packages/database/scripts
RUN npm ci

COPY . .
RUN npm run prisma:generate

EXPOSE 3000 3001 3003
CMD ["npm", "run", "dev"]
