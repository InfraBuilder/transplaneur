#!/bin/bash

case "$1" in
    transplaneur-gateway|gateway|gw)
        exec /usr/local/bin/transplaneur-gateway
        ;;
    transplaneur-sidecar|sidecar)
        exec /usr/local/bin/transplaneur-sidecar
        ;;
    *)
        exec "$@"
esac
