# myip

A example `hyper-mcp` plugin that tell you your IP address, using Cloudflare.

This is an example of how to use HTTP with `hyper-mcp`.

To use this, you will need to update your config like this. Note the `allowed_host` in `runtime_config` because we're using Cloudflare for this.

```json
{
  "plugins": [
    {
      "name": "time",
      "path": "/home/anh/Code/hyper-mcp/wasm/time.wasm"
    },
    {
      "name": "qr_code",
      "path": "oci://ghcr.io/tuananh/qrcode-plugin:latest"
    },
    {
      "name": "hash",
      "path": "oci://ghcr.io/tuananh/hash-plugin:latest"
    },
    {
      "name": "myip",
      "path": "oci://ghcr.io/tuananh/myip-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["1.1.1.1"]
      }
    }
  ]
}
```