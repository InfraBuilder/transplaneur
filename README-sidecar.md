# Transplaneur Sidecar

## Usage

To use Transplaneur Sidecar, run the following command with the appropriate flags:

<code>
transplaneur sidecar [flags]
</code>

### Optional flags/environment variables

These flags are optional, and you can either set them as command-line flags or environment variables.

- `-gateway-id=default` or `GATEWAY_ID`: Identifier for this gateway (default: "default").
- `-http-port=8080` or `HTTP_LISTEN_PORT`: HTTP listen port (default: 8080).

### Help flags

Use these flags to get help with the command:

- `-h` or `-help`: Print help.

## Examples

To run Transplaneur Sidecar with default settings:

<code>
transplaneur sidecar
</code>

To run Transplaneur Sidecar with custom settings:

<code>
transplaneur sidecar -gateway-id=mygateway -http-port=8081
</code>

Or with environment variables:

<code>
export GATEWAY_ID=mygateway
export HTTP_LISTEN_PORT=8081

transplaneur sidecar
</code>