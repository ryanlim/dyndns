# dyndns
Dynamically update your host DNS records, either via an HTTP endpoint or RFC 2136.

## Requirements
* Python 3.6 or greater.
* For **HTTP mode**: an HTTP endpoint that accepts the JSON update protocol (e.g. `https://dyndns.limau.net/update`).
* For **RFC 2136 mode**: a DNS server configured to accept dynamic updates, a configured zone, and an authorized TSIG key. Requires DNSPython and netifaces.

## Configuration file

The config file is a JSON file (conventionally `config.json`). The update mode is selected automatically based on which keys are present:

* If `endpoint` and `bearer_token` are present → **HTTP mode**
* Otherwise → **RFC 2136 mode**

See `config.example.json` (HTTP) and `examples/config.json` (RFC 2136) for starter templates.

### Common options

| key | type | description |
|-----|------|-------------|
| `zone` | string | The zone name being updated, e.g. `home.example.com`. |
| `host` | string | The primary record name to set or update, e.g. `myhost`. |
| `alt_names` | array | (Optional) list of other names to alias to this host via CNAME. |
| `has_bonjour` | boolean | (Optional, default: `false`) Update the `host-wa` AAAA record with the local Bonjour/utun0 address. |
| `has_local` | boolean | (Optional, default: `false`) Update the `host-local` A record with the LAN address. |
| `use_ipv6_slaac` | boolean | (Optional, default: `false`) Prefer the stable SLAAC address for IPv6 over the public privacy address. |
| `debug` | boolean | (Optional, default: `false`) Print config, operations, and responses at runtime. |
| `urllib_timeout` | int | (Optional, default: `10`) HTTP request timeout in seconds. |

### HTTP mode options

| key | type | description |
|-----|------|-------------|
| `endpoint` | string | The HTTPS update endpoint URL, e.g. `https://dyndns.limau.net/update`. |
| `bearer_token` | string | Bearer token for authorization. |

### RFC 2136 mode options

| key | type | description |
|-----|------|-------------|
| `zone_master` | string | The primary DNS server to send updates to (hostname or IP). |
| `tsigkeyring` | dict | Required fields: `name`, `secret`, and `keyalgorithm`. Valid algorithms: `hmac-md5`, `hmac-sha256`, `hmac-sha512`. |
| `dnspython_timeout` | int | (Optional, default: `10`) DNS TCP timeout in seconds. |

## Usage
```
$ python3 nsupdate.py <path to config.json>
```

Optionally build with PyInstaller to create a bundled Python application.
