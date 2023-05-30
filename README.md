# dyndns
Dynamically update your host DNS name via rfc2136.

## Requirements
* A DNS server configured to accept dynamic DNS updates.
* A configured zone and key authorized to update that zone.
* Python 3.6 or greater.
* DNSPython.

## Configuration file
The config file is just a JSON file named config.json.
### Configuration file definition
| key | type | description |
|-----|------|-------------|
| `zone_master` | string | The primary DNS server you will be sending the update to. |
| `zone` | string | The zone name you will be updating. |
| `host` | string | The primary record name to set or update. |
| `tsigkeyring` | dict | Required fields are `name` and `secret` matching the host key and secret. |
| `alt_names` | array | (Optional) list of other names you want to be associated with. |
| `has_bonjour` | boolean | (Optional, default: `false`) Update the bonjour host entry. |
| `has_local` | boolean | (Optional, default: `false`) Update the local host entry. This is typically the $hostname-local address. |
| `debug` | boolean | (Optional, default: `false`) Set to `true` to see what gets passed to nsupdate. |

## Usage
```
$ python3 nsupdate.py <path to config.json>
```

Optionally build with PyInstaller to create a bundled Python application.
