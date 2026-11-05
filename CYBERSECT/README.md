# AIR-DS Enterprise Security Gateway & Multi-Sensor Defense Shield

Repository: [github.com/Lunzzx414/air-ds](https://github.com/Lunzzx414/air-ds)

AIR-DS Enterprise is a local Security Operations Center (SOC) dashboard and multi-sensor
gateway. This guide covers preparing the environment, starting the backend, connecting
the dashboard, and configuring its data sources.

## Features

The dashboard uses `app.main` and provides authenticated access to incident history,
raw telemetry, weighted resource anomaly scoring, FIM baseline comparison, local malware
hash lookup, file inspection, configuration auditing, and read-only SQLite schema analysis.
The SQLite analyzer accepts uploaded database snapshots up to 16 MiB and reports tables,
columns, primary keys, and foreign keys without reading table rows or executing stored
SQL. Threat intelligence and proxy attack history are kept in separate SQLite databases.
An ASGI proxy sensor inspects requests before they reach FastAPI routes, blocks detected
SQL injection/XSS patterns and known malware hashes, and persists event metadata and a
request fingerprint without storing request bodies. Its local file heuristics and
signatures are defensive indicators, not a substitute for a full malware sandbox or
network-edge WAF. The active resource endpoint is a weighted threshold scorer; the
separate PyTorch model definition has no trained weights and is not loaded by the API.
Reported incident responses are recommendations only; firewall and container enforcement
integrations are not configured.

The dashboard offers bounded TCP discovery for a single private/loopback IP, checking
only a short allowlist of common ports. It does not identify operating systems or test
vulnerabilities. Public IPs, hostnames, CIDRs, arbitrary ports, exploit checks, and
credentialed scans are not supported. The former SQLMap/Nikto API routes return
`501 Not Implemented` rather than running active tests or showing simulated findings.
The global attack map uses the supplied `app/dashboard/worldmap.jpg` image and can show
real proxy detections geolocated with either a local GeoLite2 City database or the
optional online `ipwho.is` provider. Country and continent summaries are derived from the
location data attached to SQLite-backed
proxy history; live events without an available location are not plotted or counted as a
country. Real detections and synthetic test incidents are shown separately. Test incidents
use fictional country assignments and reserved documentation IP ranges; private IPs are
never geolocated. The image has no political borders, and IP location is approximate and
does not identify a person.

The API allows CORS requests from any origin for API-key-based browser clients. Cookie
credentials are disabled, and protected API routes still require `X-AIR-DS-KEY`.

---

## Requirements

- Linux, macOS, or WSL2 with Bash. The launch script is not a PowerShell script.
- Python 3.10 or newer, `pip`, and Python's `venv` module.
- OpenSSL for first-run generation of private API and signing keys.
- A browser. Internet access is needed for the dashboard's CDN-hosted UI libraries and
  for online IP geolocation if that provider is enabled.

Install the prerequisites on Debian/Ubuntu/WSL if they are missing:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip openssl
```

## Prepare the project

Clone the project and enter its root directory:
```bash
git clone https://github.com/Lunzzx414/air-ds.git
cd air-ds
```

`run_local.sh` expects the virtual environment in a sibling directory named `venv`.
Create it, activate it, and install the dependencies listed in `requirements.txt`:
```bash
python3 -m venv ../venv
source ../venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The app uses Python packages only; SQLite is included with Python, and its databases are
created automatically on first startup. No separate database server is needed.

## Start the server and open the website

From the project root, run:
```bash
./run_local.sh
```

To see server output directly in VS Code, open **Terminal → New Terminal**, make sure the
terminal is in the project root, and run the same command. Keep that terminal open while
using the dashboard; press **Ctrl+C** there to stop the server.

Open the dashboard at <http://localhost:8012/dashboard>. The API health endpoint is
<http://localhost:8012/> and interactive API documentation is at
<http://localhost:8012/docs>. By default the server listens only on `127.0.0.1`, so it is
available on this computer and is not exposed to the local network.

On the first launch, the script creates `~/.config/air-ds/environment`, generates an
`AIR_DS_API_KEY` and `SECRET_KEY`, prints the API key in the terminal, then starts the
server. Enter that API key in the dashboard to connect. It is held in the current page
only, so you must enter it again after reloading the dashboard. The key is stable across
restarts: the script reuses the saved configuration and creates new keys only if that
configuration file is deleted. Keep the key private. On Linux, the config directory and
file are restricted to `700` and `600` permissions.

The dashboard's CORS policy allows browser requests from any origin, but this does not
make the localhost server reachable from other computers. Cookie credentials are disabled,
and protected API routes still require the API key.

### Optional settings

The first-run configuration defaults to local MaxMind lookup. Select a geolocation provider
in `~/.config/air-ds/environment` by setting:
```text
AIR_DS_GEOLOCATION_PROVIDER=ipwhois
```
Restart the server after changing the setting. The online provider sends public event IPs
to `ipwho.is` over HTTPS and returns approximate country/continent and map coordinates;
lookup results are cached in memory. Private and loopback IPs are never sent to the
provider and cannot be assigned a real country. Alternatively, use the default `maxmind`
provider with a licensed GeoLite2 City database and set its path in the shell before
launching:
```bash
export AIR_DS_GEOLITE2_CITY_DB_PATH=/path/to/GeoLite2-City.mmdb
./run_local.sh
```

Other supported shell overrides include:
```bash
AIR_DS_PORT=8013 ./run_local.sh
AIR_DS_DATA_DIR=/path/to/air-ds-data ./run_local.sh
SQLITE_DATABASE_PATH=/path/to/application.sqlite ./run_local.sh
```
The first changes the listening port; the second changes where AIR-DS creates its threat
intelligence and proxy-history databases; the third selects a separate SQLite file for
read-only schema analysis. Set an override each time you launch, or export it in your
shell profile if you want it to persist.

---

## Dashboard use and database setup

The dashboard's **SQLite database static analysis** button audits the SQLite file selected
by `SQLITE_DATABASE_PATH` in read-only mode. You can also upload a database snapshot (up to
16 MiB). The API supports
`GET /api/v1/security/analyze-sqlite/live` for the configured database and
`POST /api/v1/security/analyze-sqlite` with multipart form field `file` for an upload;
both require the `X-AIR-DS-KEY` header.

The app's own databases are created automatically under `./data` by default:
`attack_history.sqlite3` stores proxy detections and `threat_intel.sqlite3` stores imported
threat-intelligence metadata. They are separate from the optional schema-audit database.

### Troubleshooting

- **`Project virtual environment missing`**: create `../venv` from the project root and
  install `requirements.txt` as shown above.
- **Port already in use**: stop the other server, or choose another port with
  `AIR_DS_PORT=8013 ./run_local.sh` and open that port's dashboard URL.
- **Dashboard says backend unavailable**: leave the launch terminal running, check the
  printed port, then reload the page.
- **Protected features reject the key**: use the API key printed by the same launch
  configuration. If needed, read `AIR_DS_API_KEY` from
  `~/.config/air-ds/environment`; never paste the `SECRET_KEY` into the dashboard.
- **No country appears on the map**: real live locations require public event IPs. Private
  addresses such as `127.0.0.1` are intentionally not geolocated. Check the geolocation
  status shown beside the map and verify the selected provider is configured.

## API-key-protected features

The API's safe network discovery and imported threat intelligence features are available
from the dashboard after entering the API key. The server does not run active
vulnerability scans; disabled scanner endpoints return `501 Not Implemented`.

### Network discovery

Use the dashboard's **Safe Network Discovery** panel, or authenticated
`POST /api/v1/scanners/network` with JSON such as:
```json
{"target":"192.168.1.10","profile":"advanced","ports":[22,80,443]}
```
The target must be one private/loopback IP. Only ports 22, 53, 80, 443, 445, 3389,
8080, and 8443 are accepted (maximum 8 per check). Host discovery and basic checks use
this same bounded TCP-connect probe. OS fingerprinting, dynamic plugin scans,
vulnerability tests (including web, Badlock, Shellshock, DROWN, and Intel AMT),
credentialed patch audits, Shadow IT discovery, and endpoint malware/ransomware scans
are not implemented; results are never fabricated. Uploaded files can still be checked
against imported malware hashes via the existing file-scan feature.

### Local threat intelligence and proxy history

Import the official CISA Known Exploited Vulnerabilities catalog into the local
threat-intelligence database:
```bash
python -m app.import_threat_intel --source cisa-kev --fetch
```
The feed can be refreshed by rerunning that command. Import authorized/local CSV
metadata exports for other feeds:
```bash
python -m app.import_threat_intel --source exploitdb --file /path/to/files_exploits.csv
python -m app.import_threat_intel --source malwarebazaar --file /path/to/malwarebazaar.csv
```
Exploit-DB metadata and MalwareBazaar SHA-256 metadata are imported only; exploit code
and malware samples are not. These sources require separately obtained CSV exports.
Unknown hashes are reported as **Unknown**, not Clean. The protected dashboard/API
provides local feed counts, CISA KEV CVE lookup, and recent sensor events. The sensor
keeps attack records in `attack_history.sqlite3`, separate from feed records in
`threat_intel.sqlite3`, and limits stored history to the latest 10,000 detections.
Protected lookup endpoints are `GET /api/v1/threat-intel/summary`,
`GET /api/v1/threat-intel/cve/{cve_id}`, `POST /api/v1/threat-intel/cve`, and
`GET /api/v1/security/attack-history`; send the configured key in `X-AIR-DS-KEY`.

Run tests from the project root:
```bash
../venv/bin/python -m pytest -q
```

---
*AIR-DS Enterprise SOC Dashboard & Gateway.*
