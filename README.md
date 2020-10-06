# nsx-search
Proof of concept CLI Tool to search the VMware NSX-T API. <br/>
Requires NSX-T 3.0 or higher.


# Syntax
```
Usage:
  -e, --endpoint string      NSX-T Manager Hostname
  -k, --insecure             Skip TLS verification. Default true.
  -m, --manager-api          User manager API. Defaults to false, which uses the policy API
  -n, --object-name string   Optional. Name of object to query. Without a name, all objects will be returned, up to 1000.
  -o, --object-type string   Type of object to query
  -p, --password string      NSX-T Manager password
  -u, --username string      NSX-T Manager username
For example:
nsxsearch -e 1.1.1.1 -u admin -p password -m -k -object <LogicalRouter> -name <t0_router> 
```