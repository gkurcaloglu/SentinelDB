# syntax=docker/dockerfile:1

# ---- builder ----
FROM node:20-alpine AS builder

WORKDIR /src

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# VITE_API_BASE_URL, Vite tarafindan derleme zamaninda statik bundle'a
# gomulur (tarayicida calisan koddur, Docker servis adi degil, gateway'in
# HOST'ta yayinlanan adresi kullanilmalidir - bkz. root README "Servis ve
# Port Tablosu").
ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# ---- runtime ----
# Statik dosyalari sunmak icin kucuk bir nginx imaji; derleyici/paket
# yoneticisi (npm/node) runtime imajina tasinmaz.
FROM nginx:1.27-alpine AS runtime

COPY --from=builder /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

# Imajda hazir gelen "nginx" kullanicisina (uid 101) gecmeden once, o
# kullanicinin yazmasi gereken dizinleri (cache, pid, log) devretmek
# gerekir; aksi halde non-root worker process baslatilamaz. 8080
# (<1024 degil) kullanildigi icin ayrica bir "cap" eklemeye gerek yoktur.
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && touch /tmp/nginx.pid && chown nginx:nginx /tmp/nginx.pid

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -q -O- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1
