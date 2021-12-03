# NetworkDiscover

Network discovery and visualization

## Usage: discover.py

`discover.py -t|--target A.B.C.D[/E][,SECOND,THIRD,...] [-s|--simple] [-n|--name NAME] [-d|--device DEVICE] [-h|--hops MAX_NUM_HOPS=10]`

| Parameter      |  | Default value     | Description |
|----------------|--|-------------------|-------------|
| _-t, --target_ | _**required**_ |     | List of hosts and networks to discover and scan. You can give multiple targets/networks by concat them with a semicolone _;_ |
| _-s, --simple_ | _Optional_ | false   | Don't do full scan, no Port- and no CVE-Scan |
| _-n, --name_   | _Optional_ | network | Give this scan an name; The database is named after this |
| _-d, --device_ | _Optional_ |         | Perform all scans on this device and not let the system choose it automatically |
| _-h, --hops_   | _Optional_ | 10      | Maximum number of hops for traceroute |


## Usage: graph.py

`graph.py [-n|--name NAME]`

| Parameter      |  | Default value     | Description |
|----------------|--|-------------------|-------------|
| _-n, --name_   | _Optional_ | network | The name of the scan to vizualize; The database is named after this |


## Usage http.py

This is a simple Web-Frontend for viewing the discovered network plan and more information.
To use this the package `simple_http_server` is needed: `pip install simple_http_server`
