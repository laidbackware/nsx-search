# nsx-search
Proof of concept CLI Tool to search the VMware NSX-T API. <br/>
Requires NSX-T 3.0 or higher.


# Syntax
```
Usage to query a Logical Router called 'tier0-gw' on the manager API:
  nsx-search -e <nsx ip/fqdn> -k -u <username> -p <password> -o LogicalRouter -n tier0-gw -m

Syntax:
  -a, --available-objects    Show available objects to search
  -e, --endpoint string      NSX-T Manager Hostname
  -h, --help                 Show help
  -k, --insecure             Skip TLS verification. Default true.
  -m, --manager-api          User manager API. Defaults to false, which uses the policy API
  -n, --object-name string   Optional. Name of object to query. Without a name, all objects will be returned, up to 1000.
  -o, --object-type string   Type of object to query
  -p, --password string      NSX-T Manager password
  -u, --username string      NSX-T Manager username
```
The output is raw JSON which can be queried by a tool such as JQ.