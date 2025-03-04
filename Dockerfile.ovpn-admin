FROM node:16-alpine3.15 AS frontend-builder
COPY ../frontend /app
RUN apk add --update python3 make g++ && cd /app && npm install && npm run build

FROM golang:1.23.6-bullseye AS backend-builder
RUN go install github.com/gobuffalo/packr/v2/packr2@latest
COPY --from=frontend-builder /app/static /app/frontend/static
COPY .. /app
ARG TARGETARCH
RUN cd /app && packr2 && env CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} go build -a -tags netgo -ldflags '-linkmode external -extldflags -static -s -w' -o ovpn-admin && packr2 clean

FROM alpine:3.21
WORKDIR /app
COPY --from=backend-builder /app/ovpn-admin /app
ARG TARGETARCH
RUN apk add --update bash easy-rsa openssl openvpn coreutils  && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    wget https://github.com/pashcovich/openvpn-user/releases/download/v1.0.4/openvpn-user-linux-${TARGETARCH}.tar.gz -O - | tar xz -C /usr/local/bin && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*
RUN if [ -f "/usr/local/bin/openvpn-user-${TARGETARCH}" ]; then ln -s /usr/local/bin/openvpn-user-${TARGETARCH} /usr/local/bin/openvpn-user; fi
