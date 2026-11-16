FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5

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
