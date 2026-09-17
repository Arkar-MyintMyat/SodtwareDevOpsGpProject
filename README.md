# ML-KEM Legacy Modernization - Baseline System

Course project for *Software Development, Maintenance & Operations* (University
of Oulu). This repository currently contains the **baseline (pre-modernization)
system** only: a simulated legacy device, an edge gateway, and a cloud service.

The baseline is intentionally imperfect. Its weaknesses are the starting point
for the post-quantum migration described in `docs/architecture.md`.

## Architecture

```
legacy_device  ---- TCP 9000, AES-128-CBC ---->  edge_gateway  ---- HTTP 8000 ---->  cloud_service
(Arduino-class,      hardcoded pre-shared key    (protocol                            (FastAPI,
 256-byte buffer,    no key establishment         translation,                          in-memory
 cannot be           unauthenticated              replay check)                         storage)
 re-flashed)
```

| Component | Path | Role |
| --- | --- | --- |
| Legacy device | `legacy_device/` | Simulates a constrained sensor node. Sends an encrypted reading every N seconds. |
| Edge gateway | `edge_gateway/` | Terminates the legacy protocol, validates frames, forwards to the cloud over HTTP. |
| Cloud service | `cloud_service/` | Ingests readings, exposes `/health` and read APIs. |

## Requirements

* Python 3.11+
* `pip install -r requirements.txt`

## Running it

Three terminals, in this order.

**1. Cloud service**

```bash
python -m uvicorn cloud_service.app:app --host 127.0.0.1 --port 8000
```

**2. Edge gateway**

```bash
python -m edge_gateway.gateway --cloud-url http://127.0.0.1:8000
```

**3. One or more devices**

```bash
python -m legacy_device.device --device-id dev-001 --interval 2
python -m legacy_device.device --device-id dev-002 --interval 2   # another terminal
```

## Checking that it works

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/devices
curl "http://127.0.0.1:8000/api/v1/telemetry?limit=5"
```

Interactive API docs are served at <http://127.0.0.1:8000/docs>.

## Wire protocol (legacy)

Each frame is one newline-terminated ASCII line:

```
<iv-hex>:<ciphertext-hex>\n
```

The plaintext inside is a pipe-delimited record:

```
DEV|<device_id>|<seq>|<temp_c>|<humidity>|<uptime_s>
```

A frame carrying a typical reading is 98 bytes, against a simulated device
buffer of 256 bytes. That headroom matters: see `docs/architecture.md` for why
it rules out running ML-KEM on the device itself.

## Known weaknesses of the baseline

These are deliberate. They are the work items for the modernization phase.

1. **No key establishment.** One AES key is hardcoded in firmware and shared by
   the whole fleet. It cannot be rotated. This is the mechanism ML-KEM replaces.
2. **Unauthenticated encryption.** AES-CBC without a MAC means tampering cannot
   be distinguished from corruption.
3. **Static gateway token.** The gateway authenticates to the cloud with a
   hardcoded bearer token.
4. **No transport security gateway -> cloud.** Plain HTTP.
5. **No store-and-forward.** Readings are dropped if the cloud is unreachable.
6. **In-memory storage only.** The cloud loses all data on restart.
7. **No automated tests, CI, containers, or metrics endpoints yet.**
8. **Shared protocol module.** `edge_gateway` imports from
   `legacy_device.protocol`, which couples two separately deployable services.

## Project status

- [x] Baseline: device, gateway, cloud running end to end
- [ ] Automated tests and baseline measurements
- [ ] Containers and CI/CD pipeline
- [ ] Crypto-agility layer and suite negotiation
- [ ] ML-KEM / hybrid integration on the gateway-cloud path
- [ ] Health checks, metrics, PQC observability
- [ ] Deployment to a test environment
