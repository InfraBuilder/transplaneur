# Transplaneur Gateway

## Usage

To use Transplaneur Gateway, run the following command with the appropriate flags or environment variables :

```
[export <VAR>=<value>]
transplaneur gateway [flags]
```

### Mandatory flags/environment variables

The following flags are required to run the gateway. You can either set them as command-line flags or environment variables.

- `-apiEndpoint=<apiEndpoint>` or `API_ENDPOINT`: The Transplaneur API endpoint, ex: '<ip/hostname>:<port>'.
- `-bearer-token=<bearer-token>` or `BEARER_TOKEN`: The API bearer token.
- `-cluster-pod-cidr=<cluster-pod-cidr>` or `CLUSTER_POD_CIDR`: The cluster CIDR for Pods.
- `-cluster-svc-cidr=<cluster-svc-cidr>` or `CLUSTER_SVC_CIDR`: The cluster CIDR for Services.

### Optional flags/environment variables

These flags are optional, and you can either set them as command-line flags or environment variables.

- `-gateway-id=default` or `GATEWAY_ID`: Identifier for this gateway (default: "default").
- `-http-port=8080` or `HTTP_LISTEN_PORT`: HTTP listen port (default: 8080).
- `-interface-name=wg0` or `WG_INTERFACE_NAME`: WireGuard interface name (default: "wg0").

### Help flags

Use these flags to get help with the command:

- `-h` or `-help`: Print help.

## Examples

To run Transplaneur Gateway with the mandatory flags:

```
transplaneur gateway \
    -apiEndpoint=192.168.1.2:8080 \
    -bearer-token=myb3ar3rt0k3n \
    -cluster-pod-cidr=10.0.0.0/16 \
    -cluster-svc-cidr=10.1.0.0/16
```

Or with environment variables:

```bash
export API_ENDPOINT=192.168.1.2:8080
export BEARER_TOKEN=myb3ar3rt0k3n
export CLUSTER_POD_CIDR=10.0.0.0/16
export CLUSTER_SVC_CIDR=10.1.0.0/16

transplaneur gateway
```

To include optional flags:

```bash
transplaneur gateway \
    -apiEndpoint=192.168.1.2:8080 \
    -bearer-token=myb3ar3rt0k3n \
    -cluster-pod-cidr=10.0.0.0/16 \
    -cluster-svc-cidr=10.1.0.0/16 \
    -gateway-id=mygateway \
    -http-port=8081 \
    -interface-name=wg1
```
