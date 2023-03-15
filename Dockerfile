FROM alpine:3.17

RUN apk add --no-cache \
    bash \
    bind-tools \
    curl \
    ncurses \
    wireguard-tools

COPY rootfs/ /

WORKDIR /var/run/transplaneur

ENTRYPOINT [ "/entrypoint.sh" ]
