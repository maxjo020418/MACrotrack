# Sniff Collector Packet DB Plan

This plan describes how to turn the temporary `sniff-collector` FastAPI receiver into a packet collection database that can support immediate inspection, StateFi-style replication, and later MAC/device re-identification experiments.

The current collector already accepts authenticated binary upload batches, parses the MACrotrack batch header, sender status, sniffer status, and per-record `SNIF` headers, then prints one JSON log line. The next step is to persist the parsed records and raw management frames in a form that keeps ingestion simple while preserving enough data for later feature extraction.

## Goals

- Store every accepted management frame with raw bytes, parsed 802.11 metadata, capture metadata, and ingest provenance.
- Filter station-originated management frames from the mixed stream of AP and station management frames without losing uncertain frames.
- Preserve timing, subtype order, sequence numbers, RSSI, channel, source sniffer, and IE structure needed for StateFi-style finite-state-machine features.
- Support later experiments that link randomized MAC bursts, fingerprint associated devices, and compare against IE/SEQ/RSSI baselines.
- Keep privacy controls explicit because raw frames contain MAC addresses, SSIDs, and other potentially identifying fields.

## DB Choice

Use PostgreSQL for the collector DB.

Reasons:

- `sniff-collector` is a server process, not an embedded logger; PostgreSQL handles concurrent writes, indexes, migrations, and long-running capture sessions better than SQLite.
- StateFi-style work needs both transactional ingest and analytical queries over millions of rows. PostgreSQL can support the ingest path now and later export clean datasets to DuckDB, Parquet, or Python notebooks.
- `bytea`, `jsonb`, array types, partial indexes, generated/materialized views, and table partitioning are useful for raw frames plus parsed metadata.
- It fits the existing empty `deploy/docker-compose.yml` direction: add `postgres` beside `sniff-collector`, then keep local development reproducible.

Do not use DuckDB as the ingest DB. DuckDB is useful later for offline analysis snapshots, but it is not the right primary database for a continuously running HTTP receiver. Do not start with TimescaleDB unless retention/compression becomes a real problem; plain PostgreSQL partitioning is enough for the first implementation.

## High-Level Ingest Flow

```text
ESP32 sender POST
    |
    v
FastAPI auth + max body check
    |
    v
parse MACrotrack batch envelope
    |
    v
insert ingest batch + optional sender/sniffer status
    |
    v
for each SNIF record:
    parse 802.11 management header
    parse subtype-specific fixed fields
    parse tagged IEs
    derive MAC roles, sequence number, subtype name, randomized bit
    classify station/AP/unknown direction
    insert frame metadata + raw payload
    |
    v
periodic jobs:
    maintain AP evidence table
    assign bursts
    extract FSM features
    train/evaluate re-identification models
```

The upload endpoint should acknowledge only after the DB transaction commits. If parsing fails, store the failed batch in an `ingest_batches` row with `parse_ok=false` and a body hash, then return the current success response shape unless the failure means the request is invalid or too large.

## Timing Model

Keep three kinds of time because each is useful for a different purpose:

- `received_at`: collector wall-clock time when the HTTP body arrived.
- `sender_uptime_ms`: sender clock from the batch header and sender status.
- `rx_ts_us_32`: ESP32 sniffer receive timestamp from each `SNIF` record.

For StateFi-style ordering and inter-frame gaps, the sniffer receive timestamp is the most important signal. It is currently a low 32-bit microsecond timestamp, so it wraps about every 71.6 minutes. Maintain a per-`(sender_device_id, source_id)` clock state that unwraps it into `rx_ts_us_unwrapped BIGINT`.

`observed_at` can be approximate:

```text
observed_at = batch.received_at - ((max_unwrapped_rx_ts_in_batch - frame.rx_ts_unwrapped) / 1e6 seconds)
```

This is good enough for session browsing and retention windows. Feature extraction should prefer `rx_ts_us_unwrapped` for ordering and deltas within one sniffer stream.

## Initial Schema

Use migrations from the beginning. Recommended Python dependencies for the implementation are `sqlalchemy`, `psycopg[binary]`, and `alembic`.

### `collector_senders`

One row per logical ESP32 sender.

```sql
create table collector_senders (
  id bigserial primary key,
  device_id text not null unique,
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  notes text
);
```

### `ingest_batches`

One row per HTTP POST.

```sql
create table ingest_batches (
  id bigserial primary key,
  sender_id bigint references collector_senders(id),
  received_at timestamptz not null,
  client_host inet,
  body_len integer not null,
  body_sha256 bytea not null,
  content_type text,
  batch_seq bigint,
  declared_record_count integer,
  parsed_record_count integer,
  payload_len bigint,
  sender_uptime_ms bigint,
  parse_ok boolean not null,
  parse_error text,
  raw_body bytea
);

create index ingest_batches_received_at_idx on ingest_batches(received_at);
create index ingest_batches_sender_seq_idx
  on ingest_batches(sender_id, batch_seq);

create index ingest_batches_sender_body_sha_idx
  on ingest_batches(sender_id, body_sha256);
```

Keep `raw_body` nullable and controlled by config. It is useful for early debugging, but storing per-frame raw payloads is usually enough.

### `mac_addresses`

A normalized MAC table lets the system join frames without repeatedly storing string addresses.

```sql
create table mac_addresses (
  id bigserial primary key,
  mac_hash bytea not null unique,
  mac_text text,
  oui bytea,
  is_local_admin boolean not null,
  is_multicast boolean not null,
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null
);
```

Default behavior should be:

- Store `mac_hash = HMAC_SHA256(COLLECTOR_MAC_HASH_KEY, raw_mac)`.
- Store `mac_text` only when `COLLECTOR_STORE_RAW_MACS=true`.
- Store `oui` only for universal, non-local-admin MACs.

### `wifi_frames`

One row per decoded `SNIF` record. Store queryable metadata here and raw bytes in `wifi_frame_payloads`.

```sql
create table wifi_frames (
  id bigserial primary key,
  batch_id bigint not null references ingest_batches(id),
  record_index integer not null,
  sender_id bigint not null references collector_senders(id),
  source_id integer not null,

  received_at timestamptz not null,
  observed_at timestamptz,
  sender_uptime_ms bigint,
  rx_ts_us_32 bigint not null,
  rx_ts_us_unwrapped bigint,

  snif_seq bigint not null,
  channel smallint not null,
  rssi smallint not null,
  frame_len integer not null,
  truncated boolean not null,
  crc16 integer not null,

  frame_control integer,
  mgmt_subtype smallint,
  mgmt_subtype_name text,
  duration_id integer,
  seq_num integer,
  frag_num integer,
  retry boolean,
  protected boolean,

  addr1_id bigint references mac_addresses(id),
  addr2_id bigint references mac_addresses(id),
  addr3_id bigint references mac_addresses(id),
  station_mac_id bigint references mac_addresses(id),
  ap_mac_id bigint references mac_addresses(id),

  ssid_hash bytea,
  ssid_len smallint,
  ssid_is_wildcard boolean,
  ie_ids smallint[],
  vendor_ouis bytea[],
  fixed_fields jsonb,
  parse_ok boolean not null,
  parse_error text,

  is_station_originated boolean,
  direction text not null default 'unknown',
  direction_confidence smallint not null default 0,
  direction_reason text,
  src_is_randomized boolean,

  unique(batch_id, record_index)
);

create index wifi_frames_received_at_idx on wifi_frames(received_at);
create index wifi_frames_observed_at_idx on wifi_frames(observed_at);
create index wifi_frames_sender_source_rx_idx
  on wifi_frames(sender_id, source_id, rx_ts_us_unwrapped);
create index wifi_frames_subtype_time_idx
  on wifi_frames(mgmt_subtype, observed_at);
create index wifi_frames_addr2_rx_idx
  on wifi_frames(addr2_id, rx_ts_us_unwrapped);
create index wifi_frames_station_rx_idx
  on wifi_frames(station_mac_id, rx_ts_us_unwrapped)
  where is_station_originated;
create index wifi_frames_ie_ids_gin_idx on wifi_frames using gin(ie_ids);
```

### `wifi_frame_payloads`

Separate raw bytes from metadata so normal queries do not pull raw frames into memory.

```sql
create table wifi_frame_payloads (
  frame_id bigint primary key references wifi_frames(id) on delete cascade,
  raw_frame bytea not null,
  raw_frame_sha256 bytea not null
);
```

Retention can later delete rows from this table while keeping parsed metadata and features.

### `access_points`

AP evidence table used by the station-originated filter.

```sql
create table access_points (
  mac_id bigint primary key references mac_addresses(id),
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  channels smallint[] not null default '{}',
  ssid_hashes bytea[] not null default '{}',
  beacon_count bigint not null default 0,
  probe_response_count bigint not null default 0,
  assoc_response_count bigint not null default 0,
  evidence_score integer not null default 0
);
```

### `station_bursts`

Burst assignment follows the StateFi/Infocom convention: frames from the same station MAC are in the same burst while adjacent inter-frame gaps are at most one second.

```sql
create table station_bursts (
  id bigserial primary key,
  station_mac_id bigint not null references mac_addresses(id),
  source_id integer,
  started_rx_ts_us bigint not null,
  ended_rx_ts_us bigint not null,
  started_at timestamptz,
  ended_at timestamptz,
  frame_count integer not null,
  probe_only boolean not null,
  full_management boolean not null,
  randomized_mac boolean,
  build_version integer not null,
  created_at timestamptz not null
);

alter table wifi_frames add column burst_id bigint references station_bursts(id);

create index station_bursts_station_time_idx
  on station_bursts(station_mac_id, started_rx_ts_us);
```

### `burst_fsm_features`

This table stores both StateFi-compatible features and expanded features.

```sql
create table burst_fsm_features (
  burst_id bigint primary key references station_bursts(id) on delete cascade,
  feature_version integer not null,
  subtype_counts jsonb not null,
  transition_counts jsonb not null,
  transition_entropy double precision,
  unique_state_count integer not null,
  total_transition_count integer not null,
  self_transition_count integer not null,
  transition_rate_hz double precision,
  mean_inter_frame_gap_ms double precision,
  p50_inter_frame_gap_ms double precision,
  p90_inter_frame_gap_ms double precision,
  max_seq_gap integer,
  ie_bitset bytea,
  ie_ids smallint[],
  channel_sequence smallint[],
  rssi_mean double precision,
  rssi_stddev double precision,
  feature_vector jsonb not null,
  created_at timestamptz not null
);
```

## 802.11 Management Parser

The collector should parse only enough of 802.11 to support storage and filtering. Do this with a dedicated parser module and unit tests, not ad hoc parsing inside the FastAPI route.

Management header offsets:

```text
0..1    frame control, little-endian
2..3    duration/id
4..9    addr1 receiver/destination
10..15  addr2 transmitter/source
16..21  addr3 BSSID
22..23  sequence control
24..    subtype-specific fixed fields, then tagged IEs
```

Frame control fields:

```text
protocol_version = frame_control & 0b11
type             = (frame_control >> 2) & 0b11
subtype          = (frame_control >> 4) & 0b1111
retry            = bit 11
protected        = bit 14
```

Management subtypes:

```text
0  Association Request
1  Association Response
2  Reassociation Request
3  Reassociation Response
4  Probe Request
5  Probe Response
8  Beacon
9  ATIM
10 Disassociation
11 Authentication
12 Deauthentication
13 Action
14 Action No Ack
```

IE parsing starts at subtype-specific offsets:

```text
Probe Request:         24
Probe Response:        36
Beacon:                36
Association Request:   28
Association Response:  30
Reassociation Request: 34
Reassociation Response:30
Authentication:        30
Deauthentication:      26
Disassociation:        26
Action:                parse category/action, then keep remaining bytes as subtype payload
```

Store full IE IDs and vendor OUIs. Store SSID as length, wildcard flag, and keyed hash by default. Avoid plaintext SSID storage unless explicitly enabled.

## Station-Originated Filtering

Do not permanently discard frames during filtering. Store every parsed management frame, then set:

- `direction`: `station`, `ap`, or `unknown`
- `is_station_originated`: boolean or null
- `station_mac_id`: usually `addr2_id` for station-originated management frames
- `ap_mac_id`: best-known AP/BSSID when available
- `direction_confidence`: 0 to 100
- `direction_reason`: short deterministic explanation

### Build AP Evidence First

Update `access_points` from high-confidence AP-originated frames:

- Beacon: `addr2` and `addr3` are AP/BSSID evidence.
- Probe Response: `addr2` and usually `addr3` are AP-like responder evidence.
- Association Response and Reassociation Response: `addr2` and `addr3` are AP evidence.
- Any management frame where `addr2 == addr3` and the subtype is AP-originated adds weaker evidence.

Increase `evidence_score` by subtype. For example: beacon `+10`, association response `+8`, probe response `+5`, weak same-addr evidence `+1`. Treat a MAC as a known AP when the score is at least `5`, or immediately after a beacon.

### Classification Rules

Apply rules in this order:

1. Malformed frames, multicast `addr2`, all-zero `addr2`, or non-management frames: `direction='unknown'`, `is_station_originated=null`.
2. If `addr2` is a known AP: `direction='ap'`, `is_station_originated=false`.
3. Beacon, Probe Response, Association Response, Reassociation Response: `direction='ap'`, `is_station_originated=false`; also update AP evidence.
4. Probe Request with unicast `addr2` that is not a known AP: `direction='station'`, `is_station_originated=true`, `station_mac_id=addr2`, confidence `95`.
5. Association Request and Reassociation Request with unicast `addr2` that is not a known AP: `direction='station'`, confidence `95`; set `ap_mac_id` from `addr3` or known `addr1`.
6. Authentication: if `addr1` or `addr3` is a known AP and `addr2` is not a known AP, mark station-originated with confidence `80`; otherwise leave unknown because authentication is exchanged in both directions.
7. Deauthentication, Disassociation, Action, Action No Ack: if `addr2` is not a known AP and `addr1` or `addr3` is a known AP, mark station-originated with confidence `70`; otherwise unknown.
8. Locally administered, unicast `addr2` with no AP evidence is a likely randomized station source. Use this only as weak supporting evidence, not as the primary rule.

This gives a high-precision station-frame subset while keeping ambiguous frames available for later review.

### Useful Views

Create a view for analysis:

```sql
create view station_management_frames as
select *
from wifi_frames
where is_station_originated is true
  and station_mac_id is not null
  and parse_ok is true;
```

Create a second view for probe-only StateFi replication:

```sql
create view station_probe_frames as
select *
from station_management_frames
where mgmt_subtype in (4);
```

Probe responses should stay in the DB but should not enter a station-originated view unless a later parser can prove the responder is a station-like P2P device.

## StateFi Replication Plan

The StateFi reference in `docs/reference/statefi.txt` uses burst-level finite-state machines over management subtypes, with a one-second maximum gap inside each burst. It evaluates two regimes:

- Full-management FSMs for associated or long-lived MACs.
- Probe-only FSMs for randomized pre-association MACs.

Implementation steps:

1. Build burst assignment jobs over `station_management_frames`, grouped by `station_mac_id`, ordered by `rx_ts_us_unwrapped`, splitting when the inter-frame gap exceeds `1_000_000` microseconds.
2. Build a separate probe-only burst mode over `station_probe_frames`.
3. For each burst, create an ordered subtype sequence and transition graph.
4. Store StateFi-compatible features:
   - number of unique states
   - total transitions
   - self-transitions
   - transition entropy
   - transition rate
   - mean inter-frame or inter-state gap
   - max sequence-number gap
   - IE bitset from observed IEs
5. Add expanded features for MACrotrack:
   - full 16x16 normalized subtype transition matrix
   - subtype count vector
   - inter-frame delay quantiles
   - burst duration and frame count
   - channel sequence and channel-switch counts
   - RSSI mean/stddev per source sniffer
   - vendor OUI for universal MACs, kept out of randomized-MAC model features unless used as a baseline
   - SSID-directed vs wildcard probe behavior using SSID hashes, not plaintext
6. Export a training dataset where raw MACs or MAC hashes are labels only, never model input.

## Re-Identification Roadmap

### Phase 1: Deterministic Labels and Baselines

Use persistent, non-randomized station MACs as proxy ground truth. For each MAC with at least two bursts:

- Positive pairs: two bursts from the same MAC.
- Negative pairs: bursts from different MACs in the same environment/time range.
- Balance positives and negatives before training.

Compute pairwise features:

- Euclidean distance between FSM vectors.
- Cosine distance between FSM vectors.
- Manhattan distance between FSM vectors.
- IE overlap similarity.
- Optional RSSI/channel similarity when multiple sniffers exist.

Train `RandomForestClassifier` first because StateFi reports RF as the strongest simple model and it works without heavy feature scaling. Add logistic regression and SVM only after the RF pipeline is reproducible.

### Phase 2: Randomized MAC Candidate Linking

For locally administered station MACs:

- Build probe-only bursts.
- Score candidate pairs within temporal windows such as 60, 120, 240, 480, and 600 seconds.
- Store results in a `device_link_scores` table with model version, score, threshold, and feature version.
- Produce clusters as hypotheses, not asserted physical identities.

Recommended table:

```sql
create table device_link_scores (
  id bigserial primary key,
  left_burst_id bigint not null references station_bursts(id),
  right_burst_id bigint not null references station_bursts(id),
  model_version text not null,
  feature_version integer not null,
  score double precision not null,
  predicted_same_device boolean not null,
  window_seconds integer,
  created_at timestamptz not null,
  unique(left_burst_id, right_burst_id, model_version)
);
```

### Phase 3: Evaluation

Track:

- Accuracy and balanced accuracy.
- Precision, recall, F1.
- Confusion matrices by environment/session.
- Discrimination accuracy using temporal windows matching the StateFi comparison.
- Ablations: FSM-only, IE-only, SEQ-only, RSSI-only, FSM+IE, FSM+IE+RSSI.

Do not report randomized-MAC cluster quality as ground truth unless there is a controlled dataset or explicit device labels.

## Privacy and Retention

Raw Wi-Fi management frames can contain identifying data. The DB should default to privacy-preserving storage:

- Require API auth in all non-local runs.
- Store MACs as keyed HMACs by default.
- Store plaintext MACs only behind `COLLECTOR_STORE_RAW_MACS=true`.
- Store SSIDs as keyed hashes plus length/wildcard flag by default.
- Keep raw frame payload retention short during routine collection, for example 7 to 30 days.
- Keep parsed metadata and FSM features longer if needed.
- Avoid exporting raw MACs, plaintext SSIDs, or raw frames into notebooks unless a specific controlled experiment requires them.

Add environment variables:

```text
COLLECTOR_DATABASE_URL=postgresql+psycopg://macrotrack:macrotrack@localhost:5432/macrotrack
COLLECTOR_DATABASE_HOST=
COLLECTOR_DATABASE_PORT=5432
COLLECTOR_DATABASE_NAME=
COLLECTOR_DATABASE_USER=
COLLECTOR_DATABASE_PASSWORD=
COLLECTOR_STORE_RAW_BODY=false
COLLECTOR_STORE_RAW_FRAMES=true
COLLECTOR_STORE_RAW_MACS=false
COLLECTOR_STORE_PLAINTEXT_SSIDS=false
COLLECTOR_MAC_HASH_KEY=<required-random-secret>
COLLECTOR_SSID_HASH_KEY=<required-random-secret>
```

## Implementation Phases

### Phase 0: Local DB Runtime

- Fill `deploy/docker-compose.yml` with PostgreSQL and optional `sniff-collector`.
- Add `deploy/.env.example` values for DB name, user, password, and collector env.
- Add collector dependencies: SQLAlchemy, psycopg, Alembic, pytest.

### Phase 1: Parser and Schema

- Move binary batch parsing out of `main.py` into a module.
- Add an 802.11 management-frame parser module.
- Add Alembic migrations for sender, batch, MAC, frame, payload, and AP evidence tables.
- Add unit fixtures for Beacon, Probe Request, Probe Response, Association Request/Response, Authentication, Deauthentication, malformed frames, and truncated frames.

### Phase 2: Persist Ingest

- In `/api/sniff/batch`, parse the body, open a DB transaction, insert the batch, insert status snapshots, bulk insert frame rows and payloads, then commit.
- Preserve the existing JSON stdout summary during transition.
- Add `/health` DB connectivity status and schema version.

### Phase 3: Station Filter

- Implement AP evidence updates.
- Implement the deterministic classification rules above.
- Add `station_management_frames` and `station_probe_frames` views.
- Add summary queries: frames per subtype, station/AP/unknown split, randomized station MAC counts, top AP evidence entries.

### Phase 4: Burst Builder

- Add a CLI command such as `uv run python -m sniff_collector.jobs build-bursts`.
- Make burst building idempotent by `build_version`.
- Support both full-management and probe-only bursts.

### Phase 5: Feature Extraction

- Add a feature job that reads bursts and writes `burst_fsm_features`.
- Export feature vectors to Parquet or CSV for notebooks.
- Add tests that known subtype sequences produce known transition counts and entropy.

### Phase 6: Re-Identification Experiments

- Build pair-generation jobs for positive/negative pairs.
- Train RF baseline with scikit-learn.
- Store model metadata and `device_link_scores`.
- Reproduce StateFi-style metrics before adding expanded MACrotrack features.

## Immediate Acceptance Criteria

The first usable DB implementation is complete when:

- A sender can POST batches to `sniff-collector` and every parsed frame appears in PostgreSQL.
- Raw frame bytes can be retrieved by frame ID.
- Querying `station_management_frames` returns Probe Request and Association Request frames from stations while excluding Beacon and normal AP Probe Response frames.
- `access_points` is populated from Beacon/Probe Response/Association Response evidence.
- A one-minute capture can be converted into station bursts using the one-second gap rule.
- At least one feature vector can be generated from a burst and traced back to the exact raw frames that produced it.
