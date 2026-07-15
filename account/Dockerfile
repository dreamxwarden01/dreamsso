# Account portal BFF — the thin proxy server + its React SPA, as one image.
# Build context is account/ (so it can build both client/ and server/). No database,
# no KEK; the only persistent state is the client key + mTLS identity, kept on a
# /config volume so they survive container recreates. Config comes from the env.

# ---- build the portal SPA (account/client/dist) ----
FROM node:22-bookworm-slim AS client
WORKDIR /client
COPY client/package*.json ./
RUN npm ci
COPY client/ ./
RUN npm run build

# ---- compile the BFF server (server/src -> server/dist) ----
FROM node:22-bookworm-slim AS server
WORKDIR /server
COPY server/package*.json server/tsconfig.json ./
RUN npm ci
COPY server/src/ ./src/
RUN npm run build

# ---- production dependencies only ----
FROM node:22-bookworm-slim AS deps
WORKDIR /server
COPY server/package*.json ./
RUN npm ci --omit=dev

# ---- runtime ----
FROM node:22-bookworm-slim AS runtime
WORKDIR /app/server
ENV NODE_ENV=production \
    PORT=4001 \
    SPA_DIST=/app/client/dist \
    OIDC_CLIENT_KEY_FILE=/config/.account-client-key.json \
    MTLS_STATE_FILE=/config/.mtls.json
COPY --from=deps   /server/node_modules ./node_modules
COPY --from=server /server/dist         ./dist
COPY --from=client /client/dist         /app/client/dist
COPY server/package.json ./
RUN mkdir -p /config && chown -R node:node /config /app
USER node
VOLUME ["/config"]
EXPOSE 4001
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4001)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
