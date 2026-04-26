# sniff-collector

Tiny FastAPI receiver for ESP32 WiFi sniff batches.

## Configure

```sh
cp .env.example .env
```

Set `COLLECTOR_API_TOKENS` to the same value as `API_TOKEN` in
`esp32_sender/include/secrets.h`. Multiple tokens can be comma-separated.

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
POST http://<collector-host>:8080/api/sniff/batch
Content-Type: application/octet-stream
Authorization: Bearer <token>
```

Every accepted POST is printed to stdout as one JSON log line. The log includes
request metadata, sanitized headers, body length/hash/hex preview, decoded
batch header, sender health status, record metadata, and a configurable frame
byte preview.

Use `COLLECTOR_LOG_RAW_BODY=true` while debugging if you want the full request
body printed as hex.
