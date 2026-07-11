# syntax=docker/dockerfile:1

# ---- builder ----
# Yalnizca gateway ikilisini derlemek icin kullanilir; runtime imajina
# hicbir Go arac zinciri kopyalanmaz.
# --platform=$BUILDPLATFORM: builder daima host mimarisinde calisir (Go
# capraz derleme yapar), boylece QEMU altinda derleyici calistirmaktan
# kaynaklanan yavasligi onler. TARGETOS/TARGETARCH BuildKit tarafindan
# hedef imaj platformuna gore otomatik doldurulur (bkz. gorev B: amd64
# sabit kodlanmamali).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY plugins/ ./plugins/

# plugins/firewall/v2.wasm zaten repoda derlenmis halde tracked'dir (bkz.
# scripts/build-wasm-plugins.ps1); burada yeniden derlenmez, oldugu gibi
# runtime asamasina tasinir.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# ---- runtime ----
# Kucuk, derleyici/paket yoneticisi kurulumu icermeyen bir calisma zamani
# imaji. Alpine, non-root kullanici olusturmak ve HTTP saglik kontrolu icin
# gereken wget'i (busybox) ekstra bir kurulum yapmadan zaten saglar.
FROM alpine:3.20 AS runtime

RUN addgroup -S sentineldb && adduser -S -G sentineldb -H -h /app sentineldb

WORKDIR /app

COPY --from=builder /out/gateway ./gateway
COPY --from=builder /src/plugins/firewall/v2.wasm ./plugins/firewall/v2.wasm
COPY config.yaml ./config.yaml

RUN chown -R sentineldb:sentineldb /app

USER sentineldb

# 5432: PostgreSQL gateway (client-facing, Simple Query Protocol)
# 8080:  salt-okunur durum/istatistik API'si (React dashboard tarafindan tuketilir)
# 9090: Prometheus /metrics endpoint'i
EXPOSE 5432 8080 9090

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -q -O- http://127.0.0.1:8080/api/status >/dev/null 2>&1 || exit 1

ENTRYPOINT ["./gateway"]
