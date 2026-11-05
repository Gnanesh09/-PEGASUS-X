# PEGASUS-X
**Local multi-agent security validation platform — Simulation + bounded real PostgreSQL lab tests**

PEGASUS-X is a resource-conscious Windows 11 research MVP. It uses LangGraph to orchestrate Red Team, Blue Team, Threat Hunter, Defense and Analyst nodes; SQLite stores events, round reports and persistent graph checkpoints; Groq is optional. The dashboard offers two explicit modes:

- **Simulation only:** creates synthetic telemetry; no packets or database tests are sent.
- **Real PostgreSQL lab tests:** runs four predefined, bounded checks against one exact, allowlisted private IPv4 VirtualBox VM and the dedicated `pegasus_lab` database.

## Real tests included

| Scenario | Real action | Safety limits |
|---|---|---|
| Authentication failures | Confirms the dedicated test role, then makes exactly **3** invalid-password login attempts | No password list, no credential discovery, no lockout configuration |
| Permission boundary | Tries one read-only `SELECT` on `restricted_demo` with `pegasus_test` | The test role must not have SELECT permission; no writes |
| Query-rate check | Runs exactly **12** `SELECT count(*)` queries on a tiny synthetic table | Read-only transaction; small fixed request count |
| Metadata check | Reads up to 10 public table names from `information_schema` | Read-only; no customer rows or secrets read |

The Blue Team's rules use those actual PostgreSQL results in Real Lab mode. If a test cannot connect or return an observation, it is marked `TEST_FAILED` rather than being falsely reported as detected. The Defense node currently performs **application-side containment only**: it records/quarantines the scenario within PEGASUS-X. It does not alter VM firewall rules, disable database accounts, or rewrite privileges.

This is a controlled database validation lab, **not** a general-purpose penetration-testing tool. It does not exploit vulnerabilities, scan networks, run arbitrary shell commands, accept arbitrary SQL, or target public systems.

## 1. Requirements

- Windows 11; Python 3.11 or 3.12 recommended.
- Intel i5 / 4 GB RAM: do not run a local LLM or multiple VMs at once.
- Internet connection for first package installation and optional Groq requests.
- Optional VirtualBox with a lightweight Ubuntu Server VM (1 vCPU, around 1 GB RAM).

## 2. Start on Windows

1. Extract this ZIP to `C:\PEGASUS-X`.
2. Install Python 3.11/3.12 and enable **Add Python to PATH**.
3. Double-click `scripts\\start_windows.bat`.
4. It creates `.venv`, installs `requirements.txt` and creates `.env` from `.env.example` if needed.
5. Open `http://127.0.0.1:8000`.
6. Choose **SIMULATION ONLY** first and start a round to verify the app.

## 3. Optional Groq configuration

Open `.env` and set `GROQ_API_KEY=your_key_here`. Keep your key private. Groq adds a defensive natural-language explanation; deterministic rules still control detection and the system remains runnable without the API.

## 4. Build the isolated VirtualBox PostgreSQL VM

### A. Create the VM

1. Install VirtualBox and create an Ubuntu Server VM (1 vCPU, 768–1024 MB RAM, 10–15 GB disk).
2. Shut down the VM, open **Settings → Network → Adapter 1**.
3. Select **Host-only Adapter**. Do **not** select Bridged Adapter and do not port-forward PostgreSQL.
4. Boot Ubuntu and run `ip -4 addr` to find the VM's host-only IPv4 address. Example: `192.168.56.10`.
5. On Windows, run `ipconfig` and note the VirtualBox Host-Only adapter address. Both IPs should be on the same private subnet.

### B. Install PostgreSQL and create the lab data

Inside Ubuntu:

```bash
sudo apt update
sudo apt install -y postgresql
sudo systemctl enable --now postgresql
```

Copy `vm/01_create_lab.sql` into the VM and run:

```bash
sudo -u postgres psql -f 01_create_lab.sql
```

Before running the SQL file, edit its two `CHANGE_THIS_..._PASSWORD` placeholders to unique passwords. The file creates only synthetic rows and two constrained, read-only roles. Run `vm/02_verify_lab.sql` as postgres afterward; `test_can_read_restricted` must be `false`. Do not put real customer data in this database.

### C. Restrict PostgreSQL to the host-only interface

Find config locations:

```bash
sudo -u postgres psql -c "SHOW config_file;"
sudo -u postgres psql -c "SHOW hba_file;"
```

Edit `postgresql.conf` and set `listen_addresses` to `'localhost,<VM_HOST_ONLY_IP>'`.

Add only the Windows host-only address to `pg_hba.conf`:

```text
host    pegasus_lab    pegasus_app     <WINDOWS_HOST_ONLY_IP>/32    scram-sha-256
host    pegasus_lab    pegasus_test    <WINDOWS_HOST_ONLY_IP>/32    scram-sha-256
```

Never use `0.0.0.0/0`. Do not expose port 5432 to the internet. Restart PostgreSQL:

```bash
sudo systemctl restart postgresql
sudo systemctl status postgresql --no-pager

# Optional: record successful and failed connection attempts in PostgreSQL logs.
sudo -u postgres psql -c "ALTER SYSTEM SET log_connections = 'on';"
sudo systemctl reload postgresql
# View the VM's PostgreSQL service log while testing:
sudo journalctl -u postgresql -f
```

From Windows PowerShell, test the private VM address:

```powershell
Test-NetConnection <VM_HOST_ONLY_IP> -Port 5432
```

### D. Enable Real Lab mode

1. Edit the project's Windows `.env` file.
2. Set both DSNs to the actual VM IP and the passwords you configured:

```env
POSTGRES_DSN=postgresql://pegasus_app:YOUR_APP_PASSWORD@192.168.56.10:5432/pegasus_lab
POSTGRES_TEST_DSN=postgresql://pegasus_test:YOUR_TEST_PASSWORD@192.168.56.10:5432/pegasus_lab
PEGASUS_LAB_HOST=192.168.56.10
PEGASUS_ENABLE_LAB_TESTS=true
```

Replace `192.168.56.10` with your VM's real host-only IP. Do not include angle brackets. URL-encode special characters in passwords (for example `@` as `%40`).

3. Restart the Windows backend.
4. In the dashboard click **CHECK DATABASE CONNECTION**. It must confirm both `pegasus_app` and `pegasus_test` connect to `pegasus_lab`.
5. Choose **REAL POSTGRESQL LAB TESTS** and start with 4 rounds. Watch the live event stream and round reports.

The backend refuses Real Lab mode unless the explicit enable flag is true, both DSNs point to the exact `PEGASUS_LAB_HOST` private IPv4 address, the database name is exactly `pegasus_lab`, and the users are exactly `pegasus_app` and `pegasus_test`.

## 5. What each agent does

- **Orchestrator:** starts bounded rounds and manages stop state.
- **Red Team:** executes the selected fixed PostgreSQL lab check or synthetic scenario, depending on mode.
- **Blue Team:** detects using actual test results in Real Lab mode, or synthetic rules in Simulation mode.
- **Threat Hunter:** correlates evidence and writes a security finding.
- **Defense:** records reversible PEGASUS-X-side containment; no OS-level changes.
- **Analyst:** scores the round and stores a JSON incident report.

LangGraph connects the nodes. `langgraph-checkpoint-sqlite` persists graph checkpoints in `data/pegasus.sqlite3`; a sequential fallback is available if the graph/checkpointer cannot initialize. The app also stores event and round history in SQLite.

## 6. API endpoints

- `GET /api/health` — dependency and live-lab readiness state.
- `GET /api/status` — engine status.
- `POST /api/start` — body example: `{"max_rounds":4,"interval":3,"mode":"real_lab"}`.
- `POST /api/stop` — requests stop.
- `GET /api/events` — stored events.
- `GET /api/rounds` — stored round scores.
- `GET /api/report/latest` — latest analyst report.
- `GET /api/lab-check` — verifies both dedicated PostgreSQL roles.
- `POST /api/reset` — clears history while stopped.

## 7. Troubleshooting

- **Live lab mode rejected:** check `PEGASUS_ENABLE_LAB_TESTS=true`, the exact VM host-only IP in all three env settings, both role passwords, and `POSTGRES_DB=pegasus_lab` in the DSNs.
- **Permission test succeeds unexpectedly:** review the SQL grants. `pegasus_test` must not have SELECT on `restricted_demo`.
- **Authentication test records fewer than 3 failures:** inspect PostgreSQL authentication configuration and the round observation; PEGASUS-X will not label fewer than two observed SQLSTATE `28P01` failures as a detection.
- **VM connection fails:** verify Host-only networking, IP/subnet, `listen_addresses`, `pg_hba.conf`, and the guest firewall. Do not switch to Bridged networking.
- **Groq rate limit/network error:** deterministic detection keeps running.
- **Port 8000 busy:** change port in `scripts/start_windows.bat` to 8010 and open `http://127.0.0.1:8010`.

## 8. Publishing responsibly

Do not commit `.env`, passwords, API keys, or logs containing sensitive values. Demonstrate only the synthetic lab database. In a resume or demo, state clearly that these are bounded PostgreSQL security validation tests, not exploitation of production systems. Report performance only after repeatable runs.
