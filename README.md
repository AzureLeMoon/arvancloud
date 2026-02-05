Arvancloud for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/TODO:PROVIDER_NAME)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for Arvancloud, allowing you to manage DNS records.

## Authenticating
This package uses the Apikey authentication method.

The provided apikey must have the `DNS administrator` and `DOMAIN administrator` permissions.

placeholder

## Example Configuration

```golang
p := arvancloud.Provider{
    AuthAPIKey: "apikey",
}
```
