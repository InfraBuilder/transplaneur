FROM golang:1.19 AS builder
WORKDIR /app
COPY transplaneur-server/ /app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/transplaneur-api -v


FROM alpine:3.17

RUN apk add --no-cache \
    bash \
    bind-tools \
    curl \
    ncurses \
    wireguard-tools

COPY rootfs/ /
COPY --from=builder /app/bin/transplaneur-api /usr/local/bin/transplaneur-api

WORKDIR /var/run/transplaneur

ENTRYPOINT [ "/entrypoint.sh" ]
