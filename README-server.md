# Transplaneur Server

## Usage

To use Transplaneur Server, run the following command with the appropriate flags:

```bash
[export <VAR>=<value>]
transplaneur server [flags]
```

### Mandatory flags/environment variables

The following flags are required to run the server. You can either set them as command-line flags or environment variables.

- `-bearer-token=<bearer-token>` or `BEARER_TOKEN`: The API bearer token.
- `-endpoint=<endpoint>` or `WG_ENDPOINT`: The WireGuard server endpoint, ex: '<ip/hostname>:<port>'.
- `-private-key=<private-key>` or `WG_PRIVATE_KEY`: The WireGuard private key.

### Optional flags/environment variables

These flags are optional, and you can either set them as command-line flags or environment variables.

- `-cidr=10.242.0.0/16` or `CIDR`: CIDR (default: 10.242.0.0/16).
- `-file-path=/data/ipam.json` or `FILE_PATH`: File path to store IPAM persistence (default: /data/ipam.json).
- `-http-port=8080` or `HTTP_LISTEN_PORT`: HTTP listen port (default: 8080).
- `-interface-name=wg0` or `WG_INTERFACE_NAME`: WireGuard interface name (default: "wg0").
- `-wg-port=51820` or `WG_LISTEN_PORT`: WireGuard listen port (default: 51820).

### Help flags

Use these flags to get help with the command:

- `-h` or `-help`: Print help.

## Examples

To run Transplaneur Server with the mandatory flags:

```bash
transplaneur server \
    -bearer-token=myb3ar3rt0k3n \
    -endpoint=192.168.1.2:51820 \
    -private-key=MYPR1V4T3K3Y
```

Or with environment variables:

```bash
export BEARER_TOKEN=myb3ar3rt0k3n
export WG_ENDPOINT=192.168.1.2:51820
export WG_PRIVATE_KEY=MYPR1V4T3K3Y

transplaneur server
```

To include optional flags:

```bash
transplaneur server \
    -bearer-token=myb3ar3rt0k3n \
    -endpoint=192.168.1.2:51820 \
    -private-key=MYPR1V4T3K3Y \
    -cidr=10.0.0.0/16 \
    -file-path=/data/ipam_custom.json \
    -http-port=8081 \
    -interface-name=wg1 \
    -wg-port=51821
```