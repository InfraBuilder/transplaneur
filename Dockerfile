FROM alpine:3.17

RUN apk add --no-cache \
    bash \
    bind-tools \
    curl \
    ncurses \
    wireguard-tools

COPY rootfs/ /

ENV TRANSPLANEUR_SVC_NAME=transplaneur-hl.transplaneur.svc.cluster.local. \
    POD_CIDR="" \
    SERVICE_CIDR=""

ENTRYPOINT [ "/entrypoint.sh" ]
