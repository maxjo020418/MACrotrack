# sniff-collector

FastAPI receiver for ESP32 WiFi sniff batches. It can run as a parser/logger
only, or persist parsed batches and raw management frames to PostgreSQL.

## Configure

```sh
cp .env.example .env
```

Set `COLLECTOR_API_TOKENS` to the same value as `API_TOKEN` in
`esp32_sender/include/secrets.h`. Multiple tokens can be comma-separated.

Set `COLLECTOR_DATABASE_URL` to enable DB writes, or set
`COLLECTOR_DATABASE_HOST`, `COLLECTOR_DATABASE_NAME`, `COLLECTOR_DATABASE_USER`,
and `COLLECTOR_DATABASE_PASSWORD`. Leave both forms blank to keep the server in
parser/logger mode. When DB writes are enabled, set long random values for
`COLLECTOR_MAC_HASH_KEY` and `COLLECTOR_SSID_HASH_KEY`; MACs and SSIDs are
stored as keyed hashes by default.

Supported auth headers:

- `Authorization: Bearer <token>` from `esp32_sender`
- `Authorization: Token <token>`
- `Authorization: Basic <anything>:<token>`
- `X-API-Token: <token>`

## Run

```sh
uv run python main.py
```

The sender default endpoint is:

```text
POST http://<collector-host>:8888/api/sniff/batch
Content-Type: application/octet-stream
Authorization: Bearer <token>
```

Every accepted POST is printed to stdout as one JSON log line. If
`COLLECTOR_DATABASE_URL` is set, the collector also stores one `ingest_batches`
row per POST, one `wifi_frames` row per parsed `SNIF` record, optional raw frame
bytes, normalized MAC rows, and AP evidence for station-frame filtering.

Use `COLLECTOR_LOG_RAW_BODY=true` while debugging if you want the full request
body printed as hex.

## Docker Compose

The deployable stack lives in `deploy/`:

```sh
cp ../deploy/.env.example ../deploy/.env
docker compose --project-directory .. -f ../deploy/docker-compose.yml --env-file ../deploy/.env up --build
```

The compose file starts PostgreSQL and this service. The Python container is
built from `sniff-collector/Dockerfile`.

The same stack also starts Grafana at `http://localhost:3000` by default. Login
with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` from `deploy/.env`.
Grafana is provisioned with:

- a read-only PostgreSQL datasource named `MACrotrack PostgreSQL`
- a starter dashboard named `MACrotrack Collector Overview`

The read-only database role is created by `deploy/postgres/init` when the
PostgreSQL volume is first initialized. If you add Grafana to an already-created
PostgreSQL volume, create that role manually or recreate the volume.
