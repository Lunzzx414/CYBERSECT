CYBERSECT SCANNER SETUP AND QUICK START
================================================

This guide explains how to prepare an Arch Linux or Debian/Ubuntu server, open the dashboard,
run the supported network checks, configure SSH/SMB audits, and use the Windows/Linux
endpoint report agent.


1. GET THE PROJECT
------------------

Clone the current CYBERSECT repository and enter its project directory:

    git clone https://github.com/Lunzzx414/CYBERSECT.git
    cd CYBERSECT

If you already have a checkout, open its project directory (the directory containing
requirements.txt and run_local.sh) instead of cloning it again.

2. INSTALL SYSTEM PREREQUISITES
-------------------------------

On Arch Linux, install the system packages with pacman:

    sudo pacman -Syu --needed python python-pip openssl openssh smbclient nmap

On Debian or Ubuntu, install the corresponding packages with apt:

    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv openssl openssh-client smbclient nmap

The scanner utilities are installed on the server running the dashboard. The SSH audit
uses the OpenSSH client, the SMB audit uses smbclient, and the safe service-script audit
uses Nmap. Nmap OS fingerprinting also needs raw-socket privileges. Ubuntu calls the SSH
client package `openssh-client`; `openssh-server` is only needed if this machine must
accept incoming SSH connections. These instructions use `python3`, since some systems
do not provide a `python` command. To optionally make `python` run Python 3 on Ubuntu,
install `python-is-python3`:

    sudo apt install python-is-python3

Create the Python virtual environment beside the CYBERSECT project directory and install
the Python dependencies:

    python3 -m venv ../venv
    source ../venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt

The project creates its SQLite databases on first startup. No database server is needed.


3. START AND CONNECT TO THE DASHBOARD
-------------------------------------

From the project directory (the directory containing run_local.sh), start the server:

    chmod +x run_local.sh
    ./run_local.sh

Keep the terminal running. The dashboard is at:

    http://localhost:8012/dashboard

Enter the AIR_DS_API_KEY printed by the launch script into the dashboard's API key field.
If the key is not available in the launch output, read only the AIR_DS_API_KEY value from:

    ~/.config/air-ds/environment

The API key is a private local password generated for this server; there is no shared or
default key. If the dashboard reports 401 Unauthorized or says the API key was cleared,
copy the Dashboard API key value from the terminal running run_local.sh and enter it again.
Do not share this key or the separate SECRET_KEY.

Do not paste or share SECRET_KEY. The dashboard holds the API key in the browser tab for
its current session. To use another port, set AIR_DS_PORT before starting the script, for
example:

    AIR_DS_PORT=8013 ./run_local.sh

After connecting with the API key, the Scan Capability Status panel checks whether SSH,
SMB, and Nmap utilities are installed. AVAILABLE means the feature and server dependency
are present; target reachability, credentials, host keys, and endpoint selection are still
required to run an audit. NOT IMPLEMENTED means the app does not perform that check.


4. PRIVATE NETWORK DISCOVERY
----------------------------

Use the Safe Network Discovery form. Enter one private IP or a private CIDR with no more
than 256 addresses, for example:

    192.168.1.0/24

The scanner accepts loopback, RFC1918, or IPv6 ULA addresses. It checks up to eight
allowlisted TCP ports: 22, 53, 80, 443, 445, 3389, 8080, and 8443. The basic check uses
bounded TCP connections and safe service observations such as SSH banners, HTTP response
headers, and SMB protocol/signing negotiation.

For Nmap service-version checks, OS identification, TLS settings, SMB protocol/signing,
and HTTP security headers, click RUN SAFE NMAP SERVICE AUDIT. It uses a fixed script
allowlist and the same private-target and port limits. It does not accept arbitrary Nmap
options or user-supplied scripts. This audit sends network probes; scan only systems you
are authorized to assess.

The basic scanner's OS hints are low confidence. Nmap OS fingerprinting requires raw
socket privileges and can fail when the server is not running with those privileges.


5. READ-ONLY SSH INVENTORY
--------------------------

The SSH audit reads Linux package update information or installed Windows hotfix inventory.
It does not install patches. The server must have an SSH client, a key under its own
~/.ssh directory, and the authorized target's host key in its known_hosts file. Host-key
checking is strict; the audit does not turn it off or accept an unknown key automatically.

In the dashboard's READ-ONLY SSH PATCH INVENTORY form, enter:

    Target:       one private IP address
    Username:     the authorized remote account
    Identity path: the server-side key path under ~/.ssh

For example, if the server runs as the root user and its key is /root/.ssh/lab_ed25519,
enter that path. Keep the key restricted to the account owner. Linux update results depend
on cached package-manager metadata; Windows output lists installed hotfixes and does not
prove that no updates are missing.


6. READ-ONLY SMB3 SHARE AUDIT
-----------------------------

The SMB audit uses smbclient to make one authenticated SMB3 share-list request to one
private IPv4 address. It lists share names only; it does not read or write files. Enter
the authorized account, optional domain, and password in the dashboard. The password is
used for that request and placed in a temporary restricted file that is removed afterward.


7. WINDOWS / LINUX ENDPOINT REPORT AGENT
----------------------------------------

Run the standard-library Python agent locally on the Windows or Linux endpoint. Select
only directories you intend to inventory. Repeat --root to add more directories. Files
larger than 50 MiB are skipped, and the report is capped at 10,000 files.

Linux example:

    python3 -m app.endpoint_agent --root /home/alice/Documents --output endpoint-report.json

Windows PowerShell example:

    python3 -m app.endpoint_agent --root "C:\Users\Alice\Documents" --output "C:\Users\Alice\endpoint-report.json"

Optional --state-file lets you choose where the local SQLite baseline is stored:

    python3 -m app.endpoint_agent --root /home/alice/Documents --output endpoint-report.json --state-file /home/alice/.local/state/cybersect.sqlite3

The agent hashes files locally. It does not upload file contents or automatically isolate,
modify, or delete anything. The generated JSON report contains relative paths, SHA-256
hashes, file sizes, and modification times. Use the dashboard's WINDOWS / LINUX ENDPOINT
REPORT file picker to submit the JSON report for comparison with locally imported malware
hash indicators.

For a demo without real device data, select:

    samples/endpoint-report-demo.json

This file is a synthetic fixture, not a real endpoint report. Its hash should return no
local indicator match unless that exact hash was imported. An unknown hash is not a clean
verdict. The baseline-change signal is a heuristic, not a ransomware determination.


8. CHECK RESULTS AND LIMITS
---------------------------

The dashboard's result dialog reports the observations from each run. A capability badge
does not mean that a target has already been scanned. The capability endpoint is:

    GET /api/v1/scanners/capabilities

Protected API requests require the X-AIR-DS-KEY header. The server binds to 127.0.0.1 by
default; keep it local unless you have configured and reviewed a secure deployment.

The app does not run exploit-category scripts, brute-force checks, or arbitrary third-party
plugins. The Badlock, Shellshock, DROWN, and Intel AMT tests are not implemented. No
automatic host quarantine, account locking, or file deletion is performed. The safe Nmap
profile is limited to its fixed packaged script list and must not be treated as a complete
vulnerability assessment.


9. TESTS AND TROUBLESHOOTING
----------------------------

Run the existing project checks from the project directory:

    python3 -m compileall -q app
    python3 -m pytest -q

If WSL reports access denied, resolve the Windows WSL launch issue before running these
commands. If the dashboard cannot start, verify that ../venv exists and contains FastAPI
and Uvicorn, then reinstall requirements.txt in the activated environment. If an SSH or
SMB audit says NEEDS SETUP, install the missing utility with your distribution's package
manager and restart the server so its capability status refreshes. SSH also requires the correct server-side key and known_hosts
entry; SMB requires a reachable authorized host and valid credentials.
