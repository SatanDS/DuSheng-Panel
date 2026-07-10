# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS build
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /src

RUN corepack enable && corepack prepare pnpm@10.6.2 --activate

COPY package.json pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm install --filter ./apps/web... --frozen-lockfile=false

COPY apps/web ./apps/web
RUN pnpm --dir apps/web build

FROM nginx:1.27-alpine AS runtime
COPY deploy/web.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/apps/web/dist /usr/share/nginx/html

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
