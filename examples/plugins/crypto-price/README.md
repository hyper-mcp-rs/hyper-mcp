# crypto_price

## Usage

```json
{
  "plugins": [
    {
      "name": "crypto_price",
      "path": "oci://ghcr.io/tuananh/crypto-price-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["api.coingecko.com"]
      }
    }
  ]
}
```

## Notes

- HTTP request need to use `pdk.NewHTTPRequest`.

```go
req := pdk.NewHTTPRequest(pdk.MethodGet, url)
resp := req.Send()
```

- We use `tinygo` for WASI support.

- Need to export `_Call` as `call` to make it consistent. Same with `describe`.

```
//export call
func _Call() int32 {
```