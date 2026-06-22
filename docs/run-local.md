# Run Local

This document describes the local development flow for BielOS Core.

## Requirements

- Node.js 22 LTS
- npm 10 or newer
- Docker with Docker Compose, when running PostgreSQL through containers

## Environment

Do not commit a real `.env` file.

Use `.env.example` only as documentation. Create a private local `.env` file when you need Docker Compose or database-backed workflows.

Required local values for Docker Compose:

- `DATABASE_URL`
- `POSTGRES_PASSWORD`

Recommended local values:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `PUBLIC_SITE_PORT`
- `HUB_PORT`
- `NEXT_PUBLIC_HUB_URL`

## Install

```bash
npm install
```

## Development

```bash
npm run dev
```

The public site and hub run as separate Next.js apps.

## Validation

Run the same checks used by CI before committing changes:

```bash
npm ci
npm run typecheck
npm run prisma:validate
npm run build
```

Use `npm install` during normal dependency work, then commit the resulting `package-lock.json` changes when dependencies intentionally change.

## Docker Compose

Docker Compose intentionally requires a local `.env` file for sensitive database configuration.

```bash
docker compose -f infra/docker-compose.yml up --build
```

Do not add real credentials, exported account data, logs, database dumps, or machine-specific paths to the repository.
