# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY apps/api/go.mod ./apps/api/go.mod
COPY apps/api/go.sum ./apps/api/go.sum
WORKDIR /src/apps/api
RUN go mod download

WORKDIR /src
COPY apps/api ./apps/api

WORKDIR /src/apps/api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dusheng-api ./cmd/api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --home-dir /app --shell /usr/sbin/nologin dusheng

WORKDIR /app
COPY --from=build /out/dusheng-api /usr/local/bin/dusheng-api
RUN mkdir -p /app/data \
  && chown -R dusheng:dusheng /app

USER dusheng
ENV DUSHENG_LISTEN=0.0.0.0:18888 \
    DUSHENG_DATABASE_URL=sqlite://data/dusheng.db
EXPOSE 18888
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:18888/healthz || exit 1

ENTRYPOINT ["dusheng-api"]
