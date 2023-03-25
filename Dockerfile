FROM golang:1.19 AS builder
WORKDIR /app
COPY . /app/
RUN /app/build.sh linux


FROM alpine:3.17

RUN apk add --no-cache \
    bash \
    bind-tools \
    curl \
    ncurses \
    wireguard-tools

COPY rootfs/ /
COPY --from=builder /app/bin/transplaneur_linux_amd64 /usr/local/bin/transplaneur

WORKDIR /var/run/transplaneur

ENTRYPOINT [ "/entrypoint.sh" ]
