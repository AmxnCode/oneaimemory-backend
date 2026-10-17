# Build from the repo root:  docker build -f backend/Dockerfile .
FROM node:22-alpine AS build

WORKDIR /app

# better-sqlite3 has no prebuild for alpine/musl, so it compiles from source.
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY backend/package.json backend/
COPY mcp-server/package.json mcp-server/
COPY desktop/package.json desktop/
COPY web-dashboard/package.json web-dashboard/

# Desktop pulls the ~100MB Electron binary, which the server image never needs.
RUN npm ci --workspace packages/shared --workspace backend --include-workspace-root

COPY tsconfig.base.json ./
COPY packages/shared packages/shared
COPY backend backend

RUN npm run build --workspace packages/shared \
 && npm run build --workspace backend

# ---------------------------------------------------------------- runtime ---
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S onecon && adduser -S onecon -G onecon

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/backend/dist ./backend/dist
COPY --from=build /app/backend/package.json ./backend/
# runMigrations() reads the .sql alongside the compiled output.
COPY --from=build /app/backend/src/db/schema.sql ./backend/src/db/schema.sql

RUN mkdir -p /app/data && chown -R onecon:onecon /app/data
USER onecon

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:4000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "backend/dist/server.js"]
