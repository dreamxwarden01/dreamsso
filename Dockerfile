# DreamSSO — the OIDC IdP + admin console, as one image.
# Multi-stage: build the admin SPA, compile the server, install prod deps, then a
# slim glibc runtime (argon2 + sharp need glibc prebuilts). Config comes from the
# environment at run time (see deploy compose); the only writable state is the
# avatar dir (/data, a volume) and the ephemeral .setup-token in the workdir.

# ---- build the admin console SPA (admin-ui/dist) ----
# admin-ui bundles ../../../src/clientNormalize.ts (shared with the server), so the
# build needs the repo's src/ present at the sibling path — mirror the repo layout.
FROM node:22-bookworm-slim AS admin
WORKDIR /app
COPY admin-ui/package*.json ./admin-ui/
RUN cd admin-ui && npm ci
COPY admin-ui/ ./admin-ui/
COPY src/ ./src/
RUN cd admin-ui && npm run build

# ---- compile the server (src -> dist) ----
FROM node:22-bookworm-slim AS server
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

# ---- production dependencies only ----
FROM node:22-bookworm-slim AS deps
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev

# ---- runtime ----
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    AVATAR_DIR=/data/avatars
COPY --from=deps   /app/node_modules ./node_modules
COPY --from=server /app/dist         ./dist
COPY --from=admin  /app/admin-ui/dist ./admin-ui/dist
COPY db/           ./db/
COPY package.json  ./
# run unprivileged; the base image ships a `node` user (uid 1000)
RUN mkdir -p /data/avatars && chown -R node:node /data /app
USER node
VOLUME ["/data"]
EXPOSE 3000
# Optional: a boot healthcheck against the always-open discovery doc / 503 page.
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
