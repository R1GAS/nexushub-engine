# NexusHub Desktop Engine — security

Design goal: users should not need to trust intentions. The Engine is a **local media proxy + optional remux helper** bound to the loopback interface. Unexpected privilege or network expansion should be difficult by construction.

See also: public Engine review repo [`nexushub-engine`](https://github.com/R1GAS/nexushub-engine) — [`engine-main.js`](https://github.com/R1GAS/nexushub-engine/blob/main/engine-main.js), [`engine-security.js`](https://github.com/R1GAS/nexushub-engine/blob/main/engine-security.js), [`engine-remux.js`](https://github.com/R1GAS/nexushub-engine/blob/main/engine-remux.js). The full NexusHub app repo is private.

## What it does

- Listen on `127.0.0.1:8787` (override with `NEXUSHUB_PROXY_HOST` / `NEXUSHUB_PROXY_PORT`)
- Proxy HTTP(S) media / playlists for allowlisted NexusHub web origins
- Optional FFmpeg remux/transcode of a single upstream URL to browser-playable MP4 (seekable via `start=`)
- Optional `ffprobe` summary of one upstream URL (container, duration, codecs) so the web app can choose direct play / remux / transcode

## What it must not do

- Bind to `0.0.0.0` by default
- Proxy to loopback, private LAN, link-local, or cloud metadata addresses
- Accept arbitrary URL schemes (`file:`, `ftp:`, `javascript:`, …)
- Download extra binaries at runtime from the network (Windows release ships `ffmpeg.exe` beside the Engine / installer; otherwise PATH / `NEXUSHUB_FFMPEG`). FFmpeg licensing notes: [`docs/ENGINE-FFMPEG-LICENSING.md`](./docs/ENGINE-FFMPEG-LICENSING.md).
- Collect telemetry by default

## Phase 1 (implemented)

### Session token

- On startup the Engine generates a random `sessionToken`.
- `/engine` returns `sessionToken` **only** when the request `Origin` is an allowlisted NexusHub origin (CORS-readable by the web app).
- `/proxy`, `/remux`, `/probe`, `/resolve`, and `/logo` require that token (`?token=`, `Authorization: Bearer`, or `X-NexusHub-Token`).
- Rewritten HLS playlists embed the token in segment proxy URLs (media elements often omit `Origin`).
- `/health` stays unauthenticated (liveness only; no token, no upstream fetch).

### SSRF / destination checks

- Only `http:` and `https:` upstreams.
- No URL userinfo.
- DNS resolution is checked; loopback, RFC1918, link-local, CGNAT, metadata, benchmarking/TEST-NET, multicast and reserved ranges are blocked.
- IPv6 is checked by parsed address, not string prefix: `::/96`, ULA, all of `fe80::/10`, site-local, Teredo, documentation and multicast are blocked, and IPv4 embedded in IPv6 (`::ffff:0:0/96` mapped, `64:ff9b::/96` NAT64, `2002::/16` 6to4) is checked against the IPv4 list. (Before this, `http://[::ffff:127.0.0.1]/` passed the filter because URL parsing normalises it to `[::ffff:7f00:1]`.)
- Redirects are re-validated on every hop.
- Engine sockets connect through a validating `lookup` (`safeLookup`), so the address actually dialled is the one that was checked (closes DNS rebinding between check and connect for `/proxy`, `/logo`, `/resolve`).
- FFmpeg inputs are limited to `-protocol_whitelist http,https,tcp,tls,crypto`, so nested playlist / key URLs cannot reach `file:`, `pipe:` etc.

### Limits

- Max URL length, redirect hops, concurrent upstream fetches, and buffered response size (see `engine-security.js` / env overrides).
- Logs use host + path only — not query strings (avoids signed CDN secrets / credentials).

### Env knobs

| Variable | Purpose |
|----------|---------|
| `NEXUSHUB_PROXY_HOST` | Bind host (default `127.0.0.1`) |
| `NEXUSHUB_PROXY_PORT` | Bind port (default `8787`) |
| `NEXUSHUB_ALLOWED_ORIGINS` | Comma-separated web origins |
| `NEXUSHUB_MAX_URL_LENGTH` | Upstream URL length cap |
| `NEXUSHUB_MAX_REDIRECTS` | Redirect hop cap |
| `NEXUSHUB_MAX_BUFFER_BYTES` | Max buffered upstream body (HLS playlists / small fetches; media `/proxy` streams) |
| `NEXUSHUB_MAX_CONCURRENT` | Max parallel upstream fetches |

## Phase 2 (implemented) — remux lockdown

- Fixed FFmpeg argument templates only (`copy` or `libx264` + AAC); no user-supplied flags.
- `/remux` query allowlist: `url`, `token`, `transcode`, `vcodec=h264`, `start` — unknown keys → 400.
- `start` must be plain decimal seconds (≤ 3 decimals, ≤ 24h); it is re-formatted with `toFixed(3)` and passed as `-ss` before `-i` (input seek). Output timestamps restart at 0, so the player adds `start` to `currentTime`. With video copy the cut lands on the keyframe at or before `start`; with `transcode=1` it is frame-exact.
- `/probe` runs `ffprobe` with a fixed template (`-show_entries … -of json`, same protocol whitelist and UA); query allowlist `url`, `token`. At most 2 probes at once, 20 s kill timer (`NEXUSHUB_PROBE_TIMEOUT_MS`), 1 MB output cap. Response is a summary (`container`, `duration`, `bitRate`, `video[]`, `audio[]`, `subtitles[]`), not raw ffprobe output. `ffprobe` is looked up via `NEXUSHUB_FFPROBE`, then beside the resolved `ffmpeg`, then the bundled/Homebrew paths; when missing, `/probe` returns 503 and `/engine` reports `probe: false`.
- Upstream URL SSRF-checked again inside remux (defense in depth).
- `spawn(..., { shell: false })`; minimal env; `cwd` = OS temp (pipe-only output, no temp media files).
- Bundled `ffmpeg.exe` (same folder as the Engine) is preferred; else `NEXUSHUB_FFMPEG` / PATH must point at a real `ffmpeg` / `ffmpeg.exe` file.
- Discovery prefers known paths + `where.exe` (no PowerShell Path scrape).
- One FFmpeg process at a time. A new `/remux` stops the running one and takes over (channel switch / seek); the superseded request gets `409` if it had not started streaming. (Previously the second request got `429` until the first FFmpeg exited.)
- Default remux wall clock **2 hours** (`NEXUSHUB_REMUX_MAX_MS`); child killed on timeout, client disconnect, or Engine shutdown (`stopRemux`).

## Phase 3 (implemented) — Windows integration is opt-in

- **No auto protocol registration** on startup.
- Console stays **visible** unless `NEXUSHUB_ENGINE_HIDE=1`.
- Tray icon **on by default** on Windows (start/stop balloon tips). Set `NEXUSHUB_ENGINE_TRAY=0` to disable.
- Protocol register/unregister via:
  - CLI: `--register-protocol` / `--unregister-protocol`
  - HTTP (session token): `/protocol/register` · `/protocol/unregister` · `/protocol/status`
  - Settings UI buttons (after Engine is running)
- Windows uses **`reg.exe`** under `HKCU` only (no admin, no service, no startup task).
- `nexushub-engine://…` launches only start the server — URL parameters are **not** executed as commands.
- `--diagnostics` prints bind address, tray/hide flags, protocol state, ffmpeg path, and what register would write — **makes no changes**.

## Phase 4 (implemented) — visibility + stop UX

- `/engine` and `/activity` report **active upstream hosts** (hostname only; no query strings).
- Kinds: `proxy`, `logo`, `resolve`, `remux`, `probe`.
- Settings shows the active list (polls while online) and build identity when present.
- **Stop Engine** → `POST /quit` only; **session token required** (allowlisted Origin alone cannot quit). Origin, if sent, must still be allowlisted.
- **Stop remux** → `/remux/stop` (token required).
- `/activity` requires the session token (same bar as media control).
- Opt-in tray (`NEXUSHUB_ENGINE_TRAY=1`) receives the session token via env and quits with `POST` + `X-NexusHub-Token`. Health checks **fail closed** on `/health?json=1` identity; tray stays open if quit fails.

## Hardening follow-ups (post v0.4.7 review)

- Web origins: **exact allowlist only** (no “any localhost port”).
- Packaged builds **refuse non-loopback bind** unless `NEXUSHUB_ENGINE_ALLOW_LAN=1`.
- Upstream fetches have a wall-clock deadline (`NEXUSHUB_PROXY_TOTAL_MS`, default 5 minutes) in addition to idle/connect timeouts.
- Residual risks documented: FFmpeg does its own DNS and follows redirects / HLS segment URLs itself, so `/remux` (and `/probe`) only validate the first URL (validate-then-connect); HLS tokens in query strings (required for media elements), bounded in-memory buffering for HLS playlists / small `/proxy` bodies (media streams are piped, not fully buffered).

## Phase 5 (implemented) — reproducible release artifacts

- `engine-build-meta.js` is stamped at build time with `version`, `commit`, `builtAt`, `channel`.
- Exposed on `/engine` (`build`) and `--diagnostics`.
- `npm run build:engine:win` (or `:mac` / default) writes under `engine-dist/`:
  - binary / zip
  - `*.sha256` sidecar
  - CycloneDX 1.5 SBOM (`NexusHub-Desktop-Engine-<version>.cdx.json`)
  - `VERIFY.md` with hash-check instructions
- Optional Windows Authenticode: set `NEXUSHUB_SIGN_CERT` (+ optional `NEXUSHUB_SIGNTOOL`, `NEXUSHUB_SIGN_PASSWORD`, `NEXUSHUB_SIGN_TIMESTAMP`) before build.
- macOS public releases still need **codesign + notarize** on a Mac (Apple Developer ID) — the build script packages the `.app` / zip and checksums; it does not notarize.

Publish the binary **together with** its `.sha256` (and preferably `VERIFY.md` + SBOM). Users should verify the hash before running.

See also **[`ENGINE-VERIFY.md`](./ENGINE-VERIFY.md)** (stable how-to on `main`). Per-release `VERIFY.md` is attached to the GitHub Release assets — it is intentionally **not** a path under `engine-dist/` on `main` (that folder is gitignored except `README.txt`).

### Provenance honesty

- Stamping `commit` into the binary / `VERIFY.md` is only meaningful when that commit is **pushed** and contains the Engine sources that were packaged.
- Building from a dirty working tree and tagging `main` at an older commit is **not** reproducible provenance. Release procedure: commit → push → tag → `npm run build:engine:win` → upload assets with matching `VERIFY.md`.
- SHA-256 ≠ publisher identity. Authenticode / [SignPath Foundation](https://signpath.org/) (free OSS path) is still required for “Verified publisher” on Windows.

## Verifying Phase 1 locally

```bash
node engine-main.js
# From an allowlisted origin page, /engine should include sessionToken.
# curl without Origin must NOT receive sessionToken.
# curl /proxy?url=http://127.0.0.1/ without token → 403
# curl /proxy?url=http://127.0.0.1/&token=… → blocked destination
```

```bash
npm test                            # node:test suites in test/ (no dependencies)
node scripts/test-engine-security.mjs   # private app repo
node engine-main.js --diagnostics   # should show version + commit
npm run build:engine:win            # SHA-256 + SBOM in engine-dist/
```

Rebuild the Windows `.exe` after Engine changes: `npm run build:engine:win`.
