# syntax=docker/dockerfile:1.7

FROM debian:bullseye-slim AS ndpi
ARG NDPI_VERSION=5.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake build-essential ca-certificates git libtool pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --branch "${NDPI_VERSION}" --depth 1 https://github.com/ntop/nDPI.git /src/ndpi
WORKDIR /src/ndpi
RUN ./autogen.sh \
    && ./configure --prefix=/opt/ndpi --with-only-libndpi --enable-shared --disable-static \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make install

FROM debian:bullseye-slim AS build
ARG VERSION=dev
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl pkg-config \
    && curl -fsSL "https://go.dev/dl/go1.25.0.linux-${TARGETARCH}.tar.gz" | tar -xz -C /usr/local \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/local/go/bin:${PATH}
COPY --from=ndpi /opt/ndpi /opt/ndpi
ENV PKG_CONFIG_PATH=/opt/ndpi/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/ndpi/lib
WORKDIR /src/apps/dpi
COPY apps/dpi/go.mod ./go.mod
COPY apps/dpi/cmd ./cmd
COPY deploy/THIRD_PARTY_NOTICES.md /src/THIRD_PARTY_NOTICES.md
RUN CGO_ENABLED=1 go test -tags ndpi ./cmd/dpi \
    && CGO_ENABLED=1 go build -trimpath -tags ndpi \
    -ldflags "-s -w -X main.version=${VERSION} -linkmode external -extldflags '-Wl,-rpath,\$ORIGIN/dusheng-dpi-lib'" \
    -o /out/dusheng-dpi ./cmd/dpi \
    && mkdir -p /out/dusheng-dpi-lib \
    && cp -a /opt/ndpi/lib/libndpi.so.5* /out/dusheng-dpi-lib/ \
    && cp /src/THIRD_PARTY_NOTICES.md /out/THIRD_PARTY_NOTICES.md \
    && env -u LD_LIBRARY_PATH /out/dusheng-dpi -h >/dev/null

FROM scratch AS artifact
COPY --from=build /out/ /
