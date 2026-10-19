#!/usr/bin/env node
/**
 * NexusHub Desktop Engine — local media proxy + optional remux (packaged as .exe via pkg).
 * Binds 127.0.0.1 by default. Phase 1: session token + SSRF checks + limits.
 * See ENGINE-SECURITY.md.
 */
const http = require("http");
const https = require("https");
const { URL } = require("url");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const remux = require("./engine-remux");
const sec = require("./engine-security");
const buildMeta = require("./engine-build-meta");

const PORT = Number(process.env.NEXUSHUB_PROXY_PORT || 8787);
const HOST = process.env.NEXUSHUB_PROXY_HOST || "127.0.0.1";
/** Opt-in: allow binding beyond loopback (dangerous — LAN exposure). */
const ALLOW_LAN_BIND = process.env.NEXUSHUB_ENGINE_ALLOW_LAN === "1";
/** Per-process secret — required on /proxy /remux /probe /resolve /logo /quit /activity (not on /health). */
const SESSION_TOKEN = sec.generateSessionToken();
const upstreamGate = sec.createConcurrencyGate();
const ENGINE_VERSION = String(buildMeta.version || "0.4.10");

function isLoopbackBindHost(host) {
  const h = String(host || "")
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  return h === "127.0.0.1" || h === "::1" || h === "localhost";
}

function assertSafeBindHost() {
  if (isLoopbackBindHost(HOST)) return;
  if (ALLOW_LAN_BIND) {
    console.warn(
      `WARNING: NEXUSHUB_PROXY_HOST=${HOST} is not loopback. Engine is reachable beyond this machine. Set only if you understand the risk.`
    );
    return;
  }
  const msg = `Refusing non-loopback bind (${HOST}). Use 127.0.0.1 (default) or set NEXUSHUB_ENGINE_ALLOW_LAN=1 to override.`;
  if (process.pkg) {
    console.error(msg);
    process.exit(1);
  }
  console.warn(`${msg} (dev warning — packaged builds exit)`);
}

/** Phase 4: in-flight upstream ops (host only — no query / credentials). */
const activeOps = new Map();
let opSeq = 0;

function hostOfUrl(url) {
  try {
    return new URL(String(url || "")).host || "(unknown)";
  } catch {
    return "(unknown)";
  }
}

function beginOp(kind, url) {
  const id = ++opSeq;
  activeOps.set(id, {
    id,
    kind: String(kind || "proxy"),
    host: hostOfUrl(url),
    startedAt: Date.now(),
  });
  return id;
}

function endOp(id) {
  activeOps.delete(id);
}

function snapshotActivity() {
  const caps = remux.getRemuxCapabilities();
  const active = [...activeOps.values()].map((op) => ({
    id: op.id,
    kind: op.kind,
    host: op.host,
    ageMs: Math.max(0, Date.now() - op.startedAt),
  }));
  if (caps.remuxBusy && caps.remuxHost) {
    active.push({
      id: "remux",
      kind: "remux",
      host: caps.remuxHost,
      ageMs: caps.remuxStartedAt ? Math.max(0, Date.now() - caps.remuxStartedAt) : 0,
    });
  }
  return {
    ok: true,
    active,
    remuxBusy: Boolean(caps.remuxBusy),
    remuxHost: caps.remuxHost || "",
    concurrent: activeOps.size,
    uptimeMs: Date.now() - startedAt,
  };
}
// Match VLC — many IPTV panels fingerprint Chrome/browser UAs and return custom errors (e.g. 458).
const UA =
  process.env.NEXUSHUB_PROXY_UA || "VLC/3.0.20 LibVLC/3.0.20";

function upstreamHeaders(parsed) {
  return {
    "User-Agent": UA,
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Icy-MetaData": "1",
    Connection: "keep-alive",
    // Empty-ish client look: some panels 458 when Referer is a web-app origin.
    Referer: `${parsed.protocol}//${parsed.host}/`,
  };
}

const ALLOWED_ORIGINS = String(
  process.env.NEXUSHUB_ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000,https://nexushub-8nb.pages.dev,https://r1gas.github.io/nexushub,https://R1GAS.github.io/nexushub"
)
  .split(",")
  .map((s) => s.trim().replace(/\/$/, ""))
  .filter(Boolean);

/** Quit when NexusHub tab stops pinging (browsers can't signal "closed" reliably). */
const IDLE_MS = Number(process.env.NEXUSHUB_ENGINE_IDLE_MS || 45000);
const STARTUP_GRACE_MS = Number(process.env.NEXUSHUB_ENGINE_STARTUP_GRACE_MS || 180000);
const STAY_ALIVE = process.env.NEXUSHUB_ENGINE_STAY === "1";
/** Console stays hidden for packaged GUI builds unless NEXUSHUB_ENGINE_HIDE=0 and a console exists. */
const HIDE_CONSOLE = process.env.NEXUSHUB_ENGINE_HIDE === "1";
/** Tray + start/stop balloons on by default (Windows). Set NEXUSHUB_ENGINE_TRAY=0 (or NO_TRAY=1) to disable. */
const ENABLE_TRAY = (() => {
  if (process.env.NEXUSHUB_ENGINE_NO_TRAY === "1") return false;
  if (process.env.NEXUSHUB_ENGINE_TRAY === "0") return false;
  if (process.env.NEXUSHUB_ENGINE_TRAY === "1") return true;
  return process.platform === "win32";
})();
const ARGV = process.argv.slice(2);
const startedAt = Date.now();
let lastClientAt = 0;
let trayProc = null;
let shuttingDown = false;

function hasCliFlag(name) {
  const flags = new Set(ARGV.map((a) => String(a || "").toLowerCase()));
  return flags.has(`--${name}`) || flags.has(`-${name}`) || flags.has(name);
}

function isProtocolLaunchArg(arg) {
  return /^nexushub-engine:/i.test(String(arg || "").trim());
}

function touchClient() {
  lastClientAt = Date.now();
}

function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    remux.stopRemux("shutdown");
  } catch {
    /* ignore */
  }
  try {
    if (trayProc && !trayProc.killed) trayProc.kill();
  } catch {
    /* ignore */
  }
  try {
    server.close();
  } catch {
    /* ignore */
  }
  setTimeout(() => process.exit(code), 150);
}

function notifyEngineStarted() {
  if (process.platform === "darwin") {
    try {
      spawn(
        "osascript",
        [
          "-e",
          'display notification "Running on 127.0.0.1:' +
            PORT +
            ' - quits when you leave NexusHub" with title "NexusHub Desktop Engine"',
        ],
        { stdio: "ignore", detached: true }
      ).unref();
    } catch {
      /* ignore */
    }
  }
}

function startTrayIcon() {
  if (!ENABLE_TRAY) return;
  if (process.platform === "darwin") {
    notifyEngineStarted();
    return;
  }
  if (process.platform !== "win32") return;
  try {
    const bundled = path.join(__dirname, "engine-tray.ps1");
    const beside = path.join(path.dirname(process.execPath), "engine-tray.ps1");
    const src = fs.existsSync(bundled) ? bundled : fs.existsSync(beside) ? beside : "";
    if (!src) return;
    const tmp = path.join(os.tmpdir(), `nexushub-engine-tray-${process.pid}.ps1`);
    fs.writeFileSync(tmp, fs.readFileSync(src));
    // Pass session token via env (not argv) so tray Quit can POST /quit authenticated.
    const trayEnv = {
      ...process.env,
      NEXUSHUB_TRAY_TOKEN: SESSION_TOKEN,
      NEXUSHUB_FRONTEND_URL: process.env.NEXUSHUB_FRONTEND_URL || "http://localhost:3000/",
    };
    trayProc = spawn(
      "powershell.exe",
      [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
        tmp,
        "-Port",
        String(PORT),
        "-EnginePid",
        String(process.pid),
        "-ExePath",
        process.execPath,
      ],
      { windowsHide: true, shell: false, stdio: "ignore", env: trayEnv }
    );
    trayProc.on("error", () => {});
  } catch {
    /* tray is optional */
  }
}

function hideConsoleWindow() {
  // Phase 3: never hide unless NEXUSHUB_ENGINE_HIDE=1 (auditable default = visible).
  if (process.platform !== "win32" || !HIDE_CONSOLE) return;
  try {
    const ps = [
      "Add-Type -Name W -Namespace N -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr GetConsoleWindow();[DllImport(\"user32.dll\")]public static extern bool ShowWindow(IntPtr h,int c);';",
      "[N.W]::ShowWindow([N.W]::GetConsoleWindow(),0)",
    ].join(" ");
    spawn("powershell.exe", ["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps], {
      windowsHide: true,
      shell: false,
      stdio: "ignore",
      detached: true,
    }).unref();
  } catch {
    /* ignore */
  }
}

function startIdleWatchdog() {
  if (STAY_ALIVE) {
    console.log("Idle quit disabled (NEXUSHUB_ENGINE_STAY=1).");
    return;
  }
  setInterval(() => {
    const now = Date.now();
    if (lastClientAt) {
      if (now - lastClientAt > IDLE_MS) {
        console.log("No NexusHub heartbeat — exiting.");
        shutdown(0);
      }
      return;
    }
    if (now - startedAt > STARTUP_GRACE_MS) {
      console.log("No NexusHub client connected — exiting.");
      shutdown(0);
    }
  }, 5000);
}

function originFromReferer(referer) {
  try {
    return new URL(String(referer || "")).origin;
  } catch {
    return "";
  }
}

function requestOrigin(req) {
  const origin = String((req.headers && req.headers.origin) || "").replace(/\/$/, "");
  if (origin) return origin;
  return originFromReferer(req.headers && req.headers.referer);
}

function isAllowedWebOrigin(origin) {
  if (!origin) return false;
  const o = String(origin).replace(/\/$/, "");
  // Exact allowlist only — no “any localhost port” trust (avoids random local pages minting tokens).
  return ALLOWED_ORIGINS.includes(o);
}

/**
 * Origin: if present, must be allowlisted.
 * Token: always required for media endpoints (HLS segments often omit Origin).
 */
function originAllowedForProxy(req) {
  const origin = requestOrigin(req);
  if (!origin) return true;
  return isAllowedWebOrigin(origin);
}

function hasValidSessionToken(req, reqUrl) {
  return sec.tokensEqual(sec.readRequestToken(req, reqUrl), SESSION_TOKEN);
}

function canUseProxy(req, reqUrl) {
  if (!originAllowedForProxy(req)) return false;
  return hasValidSessionToken(req, reqUrl);
}

function denyProxy(req, res, reason) {
  console.log(`  ↳ BLOCKED ${reason} origin=${requestOrigin(req) || "(none)"}`);
  send(
    res,
    403,
    reason.includes("token")
      ? "Missing or invalid Engine session token. Open NexusHub so it can read /engine, then retry.\n"
      : `Proxy locked to NexusHub web origins only:\n${ALLOWED_ORIGINS.join("\n")}\n`,
    { "Content-Type": "text/plain; charset=utf-8" },
    req
  );
}

function corsHeadersFor(req, { allowUnauthenticated = false } = {}) {
  const origin = requestOrigin(req);
  const headers = {
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Private-Network": "true",
    "Cache-Control": "no-store",
    Vary: "Origin",
  };
  if (isAllowedWebOrigin(origin)) headers["Access-Control-Allow-Origin"] = origin;
  else if (allowUnauthenticated && !origin) {
    headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0] || "http://localhost:3000";
  }
  return headers;
}

function send(res, status, body, headers = {}, req = null, corsOpts = {}) {
  const payload = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  res.writeHead(status, {
    ...(req ? corsHeadersFor(req, corsOpts) : {}),
    "Content-Length": String(payload.length),
    ...headers,
  });
  res.end(payload);
}

function proxyHref(target) {
  return `http://${HOST}:${PORT}/proxy?url=${encodeURIComponent(target)}&token=${encodeURIComponent(SESSION_TOKEN)}`;
}

function rewriteM3u8(text, baseUrl) {
  const base = new URL(baseUrl);
  return String(text || "")
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      if (trimmed.startsWith("#")) {
        return line.replace(/URI="([^"]+)"/gi, (_m, uri) => {
          try {
            return `URI="${proxyHref(new URL(uri, base).href)}"`;
          } catch {
            return _m;
          }
        });
      }
      try {
        return proxyHref(new URL(trimmed, base).href);
      } catch {
        return line;
      }
    })
    .join("\n");
}

/** Slow panels / huge m3u_plus lists often need >30s TTFB; PowerShell waits longer by default. */
const UPSTREAM_TIMEOUT_MS = Number(process.env.NEXUSHUB_PROXY_TIMEOUT_MS || 180000);
const UPSTREAM_IDLE_MS = Number(process.env.NEXUSHUB_PROXY_IDLE_MS || 60000);
/** Hard wall clock for a single upstream fetch (including redirects). */
const UPSTREAM_TOTAL_MS = Number(process.env.NEXUSHUB_PROXY_TOTAL_MS || 300000);

async function fetchUpstream(targetUrl, redirectsLeft = sec.MAX_REDIRECTS, kind = "proxy") {
  const opId = beginOp(kind, targetUrl);
  await upstreamGate.acquire();
  try {
    const work = fetchUpstreamInner(targetUrl, redirectsLeft);
    if (!UPSTREAM_TOTAL_MS || UPSTREAM_TOTAL_MS <= 0) return await work;
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Upstream total deadline exceeded")), UPSTREAM_TOTAL_MS);
      timer.unref?.();
    });
    try {
      return await Promise.race([work, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  } finally {
    upstreamGate.release();
    endOp(opId);
  }
}

function fetchUpstreamInner(targetUrl, redirectsLeft) {
  return new Promise((resolve, reject) => {
    sec
      .assertSafeUpstreamUrl(targetUrl)
      .then((parsed) => {
        const lib = parsed.protocol === "https:" ? https : http;
        const req = lib.request(
          parsed,
          {
            method: "GET",
            headers: upstreamHeaders(parsed),
            lookup: sec.safeLookup,
          },
          (up) => {
            req.setTimeout(UPSTREAM_IDLE_MS);
            const status = up.statusCode || 502;
            if ([301, 302, 303, 307, 308].includes(status) && up.headers.location && redirectsLeft > 0) {
              up.resume();
              try {
                const next = new URL(up.headers.location, parsed).href;
                resolve(fetchUpstreamInner(next, redirectsLeft - 1));
              } catch (error) {
                reject(error);
              }
              return;
            }
            const chunks = [];
            let total = 0;
            let aborted = false;
            up.on("data", (c) => {
              if (aborted) return;
              total += c.length;
              if (total > sec.MAX_BUFFER_BYTES) {
                aborted = true;
                req.destroy();
                reject(new Error("Upstream response too large"));
                return;
              }
              chunks.push(c);
            });
            up.on("end", () => {
              if (aborted) return;
              resolve({
                status,
                headers: up.headers || {},
                body: Buffer.concat(chunks),
                finalUrl: parsed.href,
              });
            });
          }
        );
        req.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
          req.destroy();
          reject(new Error("Upstream timeout"));
        });
        req.on("error", reject);
        req.end();
      })
      .catch(reject);
  });
}

/** Follow redirects only — never download media (TorBox/debrid permalinks → final CDN). */
async function resolveRedirects(targetUrl, redirectsLeft = sec.MAX_REDIRECTS) {
  await upstreamGate.acquire();
  try {
    return await resolveRedirectsInner(targetUrl, redirectsLeft);
  } finally {
    upstreamGate.release();
  }
}

function resolveRedirectsInner(targetUrl, redirectsLeft) {
  return new Promise((resolve, reject) => {
    sec
      .assertSafeUpstreamUrl(targetUrl)
      .then((parsed) => {
        const lib = parsed.protocol === "https:" ? https : http;
        let settled = false;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          resolve(value);
        };
        const fail = (error) => {
          if (settled) return;
          settled = true;
          reject(error);
        };
        const req = lib.request(
          parsed,
          {
            method: "GET",
            headers: upstreamHeaders(parsed),
            lookup: sec.safeLookup,
          },
          (up) => {
            const status = up.statusCode || 502;
            if ([301, 302, 303, 307, 308].includes(status) && up.headers.location && redirectsLeft > 0) {
              up.resume();
              try {
                const next = new URL(up.headers.location, parsed).href;
                resolveRedirectsInner(next, redirectsLeft - 1).then(finish, fail);
              } catch (error) {
                fail(error);
              }
              return;
            }
            up.resume();
            req.destroy();
            finish({ finalUrl: parsed.href, status });
          }
        );
        req.setTimeout(20000, () => {
          req.destroy();
          fail(new Error("Resolve timeout"));
        });
        req.on("error", (error) => {
          if (settled) return;
          if (error && /aborted|ECONNRESET|socket hang up/i.test(String(error.message || error))) {
            finish({ finalUrl: parsed.href, status: 200 });
            return;
          }
          fail(error);
        });
        req.end();
      })
      .catch(reject);
  });
}

function isPlaylist(contentType, body, targetUrl) {
  const ct = String(contentType || "").toLowerCase();
  if (ct.includes("mpegurl") || ct.includes("m3u")) return true;
  if (/\.m3u8?(?:\?|$)/i.test(String(targetUrl || ""))) return true;
  const head = Buffer.isBuffer(body) ? body.slice(0, 64).toString("utf8") : String(body || "").slice(0, 64);
  return head.trimStart().startsWith("#EXTM3U");
}

function looksLikePlaylistUrl(url) {
  return /\.m3u8?(?:\?|$)/i.test(String(url || ""));
}

function pickStreamResponseHeaders(upHeaders) {
  const out = {};
  const allow = [
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "content-disposition",
    "last-modified",
    "etag",
  ];
  for (const key of allow) {
    const val = upHeaders && (upHeaders[key] ?? upHeaders[key.toLowerCase()]);
    if (val != null && val !== "") out[key] = val;
  }
  if (!out["accept-ranges"] && !out["Accept-Ranges"]) out["Accept-Ranges"] = "bytes";
  return out;
}

/**
 * Stream media through the Engine (no full-body buffer). Forwards Range for seeking.
 * Playlists must use buffered fetchUpstream + rewriteM3u8 instead.
 */
function streamProxyToClient(clientReq, clientRes, targetUrl, redirectsLeft = sec.MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    sec
      .assertSafeUpstreamUrl(targetUrl)
      .then((parsed) => {
        const lib = parsed.protocol === "https:" ? https : http;
        const headers = upstreamHeaders(parsed);
        if (clientReq.headers.range) headers.Range = clientReq.headers.range;
        if (clientReq.headers["if-range"]) headers["If-Range"] = clientReq.headers["if-range"];

        const upReq = lib.request(parsed, { method: "GET", headers, lookup: sec.safeLookup }, (up) => {
          const status = up.statusCode || 502;
          if ([301, 302, 303, 307, 308].includes(status) && up.headers.location && redirectsLeft > 0) {
            up.resume();
            try {
              const next = new URL(up.headers.location, parsed).href;
              streamProxyToClient(clientReq, clientRes, next, redirectsLeft - 1).then(resolve, reject);
            } catch (error) {
              reject(error);
            }
            return;
          }

          const type = String(up.headers["content-type"] || "");
          if (looksLikePlaylistUrl(parsed.href) || looksLikePlaylistUrl(targetUrl) || /mpegurl|m3u8/i.test(type)) {
            up.resume();
            const err = new Error("Playlist responses must use buffered proxy rewrite");
            err.code = "PLAYLIST_NEEDS_BUFFER";
            reject(err);
            return;
          }

          if (status === 458 || status === 884) {
            up.resume();
            const err = new Error(`IPTV panel refused this stream (HTTP ${status})`);
            err.code = "PANEL_REFUSE";
            err.status = status;
            reject(err);
            return;
          }

          if (clientRes.writableEnded || clientRes.headersSent) {
            up.resume();
            resolve();
            return;
          }

          console.log(
            `  ↳ stream ${status} ${type || "octet"} host=${sec.safeLogHost(parsed.href)}${
              headers.Range ? ` ${headers.Range}` : ""
            }`
          );

          clientRes.writeHead(status, {
            ...corsHeadersFor(clientReq),
            ...pickStreamResponseHeaders(up.headers || {}),
            "Cache-Control": "no-store",
          });

          let settled = false;
          const settle = (fn, arg) => {
            if (settled) return;
            settled = true;
            fn(arg);
          };
          const killUpstream = () => {
            try {
              upReq.destroy();
            } catch {
              /* ignore */
            }
            try {
              up.destroy();
            } catch {
              /* ignore */
            }
          };

          up.on("error", (error) => {
            killUpstream();
            if (!clientRes.writableEnded) {
              try {
                clientRes.destroy();
              } catch {
                /* ignore */
              }
            }
            settle(reject, error);
          });
          clientRes.on("error", () => {
            killUpstream();
            settle(resolve);
          });
          clientReq.on("aborted", () => {
            killUpstream();
            settle(resolve);
          });
          clientRes.on("close", () => {
            killUpstream();
            settle(resolve);
          });

          up.pipe(clientRes);
          clientRes.on("finish", () => settle(resolve));
        });

        upReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
          upReq.destroy();
          reject(new Error("Upstream timeout"));
        });
        upReq.on("error", reject);
        upReq.end();
      })
      .catch(reject);
  });
}

const PROTOCOL_SCHEME = "nexushub-engine";
const WIN_PROTOCOL_KEY = `HKCU\\Software\\Classes\\${PROTOCOL_SCHEME}`;

function runReg(args) {
  const result = require("child_process").spawnSync("reg.exe", args, {
    windowsHide: true,
    shell: false,
    encoding: "utf8",
    timeout: 8000,
  });
  return result;
}

function protocolCommandWindows() {
  // Launch this executable with the URL as argv[1] — never a shell or VBS by default.
  const exePath = process.execPath;
  return `"${exePath}" "%1"`;
}

function isProtocolRegisteredWindows() {
  if (process.platform !== "win32") return false;
  try {
    const result = runReg(["query", WIN_PROTOCOL_KEY, "/v", "URL Protocol"]);
    return result.status === 0;
  } catch {
    return false;
  }
}

function registerProtocolWindows() {
  if (process.platform !== "win32") {
    return { ok: false, error: "Windows only" };
  }
  try {
    const command = protocolCommandWindows();
    const steps = [
      ["add", WIN_PROTOCOL_KEY, "/ve", "/d", "URL:NexusHub Desktop Engine", "/f"],
      ["add", WIN_PROTOCOL_KEY, "/v", "URL Protocol", "/d", "", "/f"],
      ["add", `${WIN_PROTOCOL_KEY}\\shell\\open\\command`, "/ve", "/d", command, "/f"],
    ];
    for (const args of steps) {
      const result = runReg(args);
      if (result.status !== 0) {
        return {
          ok: false,
          error: String(result.stderr || result.stdout || "reg.exe failed").trim() || "reg.exe failed",
        };
      }
    }
    return { ok: true, command, key: WIN_PROTOCOL_KEY };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error) };
  }
}

function unregisterProtocolWindows() {
  if (process.platform !== "win32") {
    return { ok: false, error: "Windows only" };
  }
  try {
    if (!isProtocolRegisteredWindows()) return { ok: true, alreadyAbsent: true };
    const result = runReg(["delete", WIN_PROTOCOL_KEY, "/f"]);
    if (result.status !== 0) {
      return {
        ok: false,
        error: String(result.stderr || result.stdout || "reg delete failed").trim() || "reg delete failed",
      };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error) };
  }
}

const MAC_INFO_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>NexusHub Desktop Engine</string>
  <key>CFBundleIdentifier</key><string>com.nexushub.desktop-engine</string>
  <key>CFBundleVersion</key><string>0.4.10</string>
  <key>CFBundleShortVersionString</key><string>0.4.10</string>
  <key>CFBundleExecutable</key><string>NexusHub-Desktop-Engine</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><false/>
  <key>CFBundleURLTypes</key>
  <array><dict>
    <key>CFBundleURLName</key><string>NexusHub Desktop Engine</string>
    <key>CFBundleURLSchemes</key><array><string>nexushub-engine</string></array>
  </dict></array>
</dict>
</plist>
`;

function registerProtocolMac() {
  if (process.platform !== "darwin") {
    return { ok: false, error: "macOS only" };
  }
  try {
    const exePath = process.execPath;
    let appBundle = "";
    const marker = ".app/Contents/MacOS/";
    const idx = exePath.indexOf(marker);
    if (idx !== -1) {
      appBundle = exePath.slice(0, idx + 4);
    } else {
      appBundle = path.join(os.homedir(), "Applications", "NexusHub Desktop Engine.app");
      const macOsDir = path.join(appBundle, "Contents", "MacOS");
      fs.mkdirSync(macOsDir, { recursive: true });
      const dest = path.join(macOsDir, "NexusHub-Desktop-Engine");
      if (path.resolve(exePath) !== path.resolve(dest)) {
        fs.copyFileSync(exePath, dest);
        try {
          fs.chmodSync(dest, 0o755);
        } catch {
          /* ignore */
        }
      }
      fs.writeFileSync(path.join(appBundle, "Contents", "Info.plist"), MAC_INFO_PLIST);
    }
    const lsregister =
      "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    spawn(lsregister, ["-f", appBundle], { stdio: "ignore", shell: false, detached: true }).unref();
    return { ok: true, appBundle };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error) };
  }
}

function unregisterProtocolMac() {
  if (process.platform !== "darwin") {
    return { ok: false, error: "macOS only" };
  }
  // LaunchServices has no simple “unregister one scheme” API; document manual removal.
  return {
    ok: true,
    note: "Remove or replace the NexusHub Desktop Engine.app URL types, then rebuild Launch Services cache if needed.",
  };
}

function registerProtocol() {
  if (process.platform === "win32") return registerProtocolWindows();
  if (process.platform === "darwin") return registerProtocolMac();
  return { ok: false, error: `Protocol registration not supported on ${process.platform}` };
}

function unregisterProtocol() {
  if (process.platform === "win32") return unregisterProtocolWindows();
  if (process.platform === "darwin") return unregisterProtocolMac();
  return { ok: false, error: `Protocol unregister not supported on ${process.platform}` };
}

function isProtocolRegistered() {
  if (process.platform === "win32") return isProtocolRegisteredWindows();
  return false;
}

function printDiagnostics() {
  const caps = remux.getRemuxCapabilities();
  const lines = [
    "NexusHub Desktop Engine — diagnostics (no changes made)",
    `  version:         ${ENGINE_VERSION}`,
    `  commit:          ${buildMeta.commit || "dev"}`,
    `  builtAt:         ${buildMeta.builtAt || "(local / unpackaged)"}`,
    `  channel:         ${buildMeta.channel || "dev"}`,
    `  bind:            ${HOST}:${PORT}`,
    `  allowLanBind:    ${ALLOW_LAN_BIND}`,
    `  packaged:        ${Boolean(process.pkg)}`,
    `  platform:        ${process.platform}`,
    `  execPath:        ${process.execPath}`,
    `  sessionToken:    (generated at runtime; not printed)`,
    `  hideConsole:     ${HIDE_CONSOLE} (set NEXUSHUB_ENGINE_HIDE=1 to hide)`,
    `  tray:            ${ENABLE_TRAY} (Windows on by default; set NEXUSHUB_ENGINE_TRAY=0 to disable)`,
    `  protocolScheme:  ${PROTOCOL_SCHEME}://`,
    `  protocolReg:     ${isProtocolRegistered() ? "registered (HKCU)" : "not registered"}`,
    `  wouldRegister:   ${process.platform === "win32" ? protocolCommandWindows() : "(n/a)"}`,
    `  ffmpeg:          ${caps.ffmpeg || "(not found)"}`,
    `  remux:           ${caps.remux}`,
    `  ffprobe:         ${caps.ffprobe || "(not found — /probe disabled)"}`,
    `  allowedOrigins:  ${ALLOWED_ORIGINS.join(", ")}`,
    `  ssrfFilter:      on`,
    `  maxBufferBytes:  ${sec.MAX_BUFFER_BYTES}`,
    `  remuxMaxMs:      ${caps.remuxMaxMs}`,
    "",
    "CLI:",
    "  --diagnostics           print this report and exit",
    "  --register-protocol     register nexushub-engine:// (opt-in)",
    "  --unregister-protocol   remove nexushub-engine://",
    "",
    "No admin rights, services, or startup tasks are used.",
  ];
  console.log(lines.join("\n"));
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || "/", `http://${HOST}:${PORT}`);
  console.log(`${req.method} ${reqUrl.pathname}${reqUrl.search ? " …" : ""}`);

  if (req.method === "OPTIONS") {
    if (!isAllowedWebOrigin(requestOrigin(req)) && requestOrigin(req)) {
      send(res, 403, "Origin not allowed\n", { "Content-Type": "text/plain; charset=utf-8" }, req);
      return;
    }
    send(res, 204, "", {}, req, { allowUnauthenticated: true });
    return;
  }

  if (reqUrl.pathname === "/health") {
    // Unauthenticated liveness only — no secrets. ?json=1 adds name/version/pid for tray checks.
    if (reqUrl.searchParams.get("json") === "1") {
      send(
        res,
        200,
        JSON.stringify({
          ok: true,
          name: "NexusHub Desktop Engine",
          version: ENGINE_VERSION,
          role: "local-stream-proxy",
          pid: process.pid,
        }),
        { "Content-Type": "application/json; charset=utf-8" },
        req,
        { allowUnauthenticated: true }
      );
      return;
    }
    send(res, 200, "NexusHub stream proxy OK\n", { "Content-Type": "text/plain; charset=utf-8" }, req, {
      allowUnauthenticated: true,
    });
    return;
  }

  if (reqUrl.pathname === "/ping") {
    // Heartbeat: allowlisted Origin or valid session token.
    const origin = requestOrigin(req);
    if (origin && !isAllowedWebOrigin(origin) && !hasValidSessionToken(req, reqUrl)) {
      denyProxy(req, res, "origin");
      return;
    }
    touchClient();
    send(
      res,
      200,
      JSON.stringify({ ok: true, idleMs: IDLE_MS, lastClientAt }),
      { "Content-Type": "application/json; charset=utf-8" },
      req,
      { allowUnauthenticated: true }
    );
    return;
  }

  if (reqUrl.pathname === "/quit") {
    // Token-only shutdown — allowlisted Origin alone must never authorize quit (CSRF).
    const method = String(req.method || "GET").toUpperCase();
    if (method !== "POST") {
      send(res, 405, "Use POST\n", { "Content-Type": "text/plain; charset=utf-8", Allow: "POST" }, req, {
        allowUnauthenticated: true,
      });
      return;
    }
    if (!hasValidSessionToken(req, reqUrl)) {
      denyProxy(req, res, "token");
      return;
    }
    // Origin, if present, must still be allowlisted (browser-facing extra check).
    const origin = requestOrigin(req);
    if (origin && !isAllowedWebOrigin(origin)) {
      denyProxy(req, res, "origin");
      return;
    }
    send(res, 200, "bye\n", { "Content-Type": "text/plain; charset=utf-8" }, req, {
      allowUnauthenticated: true,
    });
    setTimeout(() => shutdown(0), 50);
    return;
  }

  if (reqUrl.pathname === "/engine") {
    const caps = remux.getRemuxCapabilities();
    const origin = requestOrigin(req);
    const issueToken = isAllowedWebOrigin(origin);
    const activity = snapshotActivity();
    const payload = {
      ok: true,
      name: "NexusHub Desktop Engine",
      version: ENGINE_VERSION,
      role: "local-stream-proxy",
      packaged: Boolean(process.pkg),
      build: {
        version: ENGINE_VERSION,
        commit: buildMeta.commit || "dev",
        builtAt: buildMeta.builtAt || "",
        channel: buildMeta.channel || "dev",
      },
      proxyPath: "/proxy?url=",
      remuxPath: caps.remuxPath,
      remux: caps.remux,
      ffmpeg: caps.ffmpeg || "",
      remuxBusy: caps.remuxBusy,
      remuxHost: caps.remuxHost || "",
      remuxMaxMs: caps.remuxMaxMs,
      // A new /remux stops the running one (channel switch / seek) instead of returning 429.
      remuxReplaces: true,
      // /remux accepts start=<seconds> (input seek; output timestamps restart at 0).
      remuxSeek: true,
      probe: caps.probe,
      probePath: caps.probePath,
      activity: activity.active,
      host: HOST,
      port: PORT,
      allowedOrigins: ALLOWED_ORIGINS,
      idleMs: IDLE_MS,
      hideConsole: HIDE_CONSOLE,
      tray: ENABLE_TRAY && process.platform === "win32",
      protocolRegistered: isProtocolRegistered(),
      protocolScheme: `${PROTOCOL_SCHEME}://`,
      platform: process.platform,
      auth: "session-token",
      security: {
        bind: `${HOST}:${PORT}`,
        ssrfFilter: true,
        maxBufferBytes: sec.MAX_BUFFER_BYTES,
        maxConcurrent: sec.MAX_CONCURRENT_UPSTREAM,
        admin: false,
        service: false,
      },
    };
    // Token only for allowlisted NexusHub origins (CORS-readable by the web app).
    if (issueToken) payload.sessionToken = SESSION_TOKEN;
    send(
      res,
      200,
      JSON.stringify(payload),
      { "Content-Type": "application/json; charset=utf-8" },
      req,
      { allowUnauthenticated: true }
    );
    return;
  }

  if (reqUrl.pathname === "/activity") {
    // Hostnames / timing — require session token (same bar as media control).
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    touchClient();
    send(
      res,
      200,
      JSON.stringify(snapshotActivity()),
      { "Content-Type": "application/json; charset=utf-8" },
      req
    );
    return;
  }

  if (reqUrl.pathname === "/remux/stop") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const stopped = remux.stopRemux("ui-stop");
    send(
      res,
      200,
      JSON.stringify({ ok: true, stopped, activity: snapshotActivity().active }),
      { "Content-Type": "application/json; charset=utf-8" },
      req
    );
    return;
  }

  if (reqUrl.pathname === "/protocol/status") {
    send(
      res,
      200,
      JSON.stringify({
        ok: true,
        scheme: `${PROTOCOL_SCHEME}://`,
        registered: isProtocolRegistered(),
        platform: process.platform,
      }),
      { "Content-Type": "application/json; charset=utf-8" },
      req,
      { allowUnauthenticated: true }
    );
    return;
  }

  if (reqUrl.pathname === "/protocol/register" || reqUrl.pathname === "/protocol/unregister") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const result =
      reqUrl.pathname === "/protocol/register" ? registerProtocol() : unregisterProtocol();
    console.log(
      `  ↳ protocol ${reqUrl.pathname.endsWith("register") ? "register" : "unregister"} → ${result.ok ? "ok" : result.error}`
    );
    send(
      res,
      result.ok ? 200 : 500,
      JSON.stringify({ ...result, registered: isProtocolRegistered() }),
      { "Content-Type": "application/json; charset=utf-8" },
      req
    );
    return;
  }

  if (reqUrl.pathname === "/resolve") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const target = reqUrl.searchParams.get("url");
    if (!target) {
      send(res, 400, JSON.stringify({ error: "Missing ?url=" }), { "Content-Type": "application/json; charset=utf-8" }, req);
      return;
    }
    touchClient();
    const opId = beginOp("resolve", target);
    try {
      const resolved = await resolveRedirects(target);
      console.log(`  ↳ resolve ${resolved.status} → ${sec.safeLogHost(resolved.finalUrl)}`);
      send(
        res,
        200,
        JSON.stringify({ ok: true, url: resolved.finalUrl, status: resolved.status }),
        { "Content-Type": "application/json; charset=utf-8" },
        req
      );
    } catch (error) {
      console.log(`  ↳ resolve ERROR ${error.message || error} host=${sec.safeLogHost(target)}`);
      send(
        res,
        502,
        JSON.stringify({ ok: false, error: String(error.message || error) }),
        { "Content-Type": "application/json; charset=utf-8" },
        req
      );
    } finally {
      endOp(opId);
    }
    return;
  }

  if (reqUrl.pathname === "/logo") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const target = reqUrl.searchParams.get("url");
    if (!target) {
      send(res, 400, "Missing ?url=\n", { "Content-Type": "text/plain; charset=utf-8" }, req);
      return;
    }
    touchClient();
    try {
      const up = await fetchUpstream(target, sec.MAX_REDIRECTS, "logo");
      const type = up.headers["content-type"] || "application/octet-stream";
      if (up.status >= 400 || (!/^image\//i.test(type) && !/octet-stream/i.test(type))) {
        send(res, up.status >= 400 ? up.status : 415, "Logo fetch failed\n", { "Content-Type": "text/plain; charset=utf-8" }, req);
        return;
      }
      if (up.body.length > 2 * 1024 * 1024) {
        send(res, 413, "Logo too large\n", { "Content-Type": "text/plain; charset=utf-8" }, req);
        return;
      }
      console.log(`  ↳ logo ${up.status} ${up.body.length}b ${sec.safeLogHost(target)}`);
      send(
        res,
        200,
        up.body,
        {
          "Content-Type": /^image\//i.test(type) ? type : "image/png",
          "Cache-Control": "public, max-age=86400",
        },
        req
      );
    } catch (error) {
      console.log(`  ↳ logo ERROR ${error.message || error} host=${sec.safeLogHost(target)}`);
      send(res, 502, `Logo error: ${error.message || error}\n`, { "Content-Type": "text/plain; charset=utf-8" }, req);
    }
    return;
  }

  if (reqUrl.pathname === "/remux") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const parsed = remux.parseRemuxQuery(reqUrl.searchParams);
    if (!parsed.ok) {
      send(res, parsed.status, `${parsed.error}\n`, { "Content-Type": "text/plain; charset=utf-8" }, req);
      return;
    }
    touchClient();
    console.log(
      `  ↳ remux start${parsed.transcodeVideo ? " (h264 transcode)" : ""}${
        parsed.startSeconds ? ` @${parsed.startSeconds}s` : ""
      } host=${sec.safeLogHost(parsed.target)}`
    );
    const result = await remux.startRemuxStream(parsed.target, res, corsHeadersFor(req), {
      transcodeVideo: parsed.transcodeVideo,
      startSeconds: parsed.startSeconds,
    });
    if (!result.ok) {
      console.log(`  ↳ remux reject ${result.status}: ${result.error}`);
      send(res, result.status, `${result.error}\n`, { "Content-Type": "text/plain; charset=utf-8" }, req);
    }
    return;
  }

  if (reqUrl.pathname === "/probe") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const parsed = remux.parseProbeQuery(reqUrl.searchParams);
    if (!parsed.ok) {
      send(res, parsed.status, JSON.stringify({ ok: false, error: parsed.error }), { "Content-Type": "application/json; charset=utf-8" }, req);
      return;
    }
    touchClient();
    const opId = beginOp("probe", parsed.target);
    try {
      const result = await remux.probeMedia(parsed.target);
      console.log(
        `  ↳ probe ${result.ok ? `${result.info.container} ${result.info.duration ?? "?"}s` : `${result.status} ${result.error}`} host=${sec.safeLogHost(parsed.target)}`
      );
      send(
        res,
        result.ok ? 200 : result.status,
        JSON.stringify(result.ok ? { ok: true, ...result.info } : { ok: false, error: result.error }),
        { "Content-Type": "application/json; charset=utf-8" },
        req
      );
    } finally {
      endOp(opId);
    }
    return;
  }

  if (reqUrl.pathname === "/proxy") {
    if (!canUseProxy(req, reqUrl)) {
      denyProxy(req, res, hasValidSessionToken(req, reqUrl) ? "origin" : "token");
      return;
    }
    const target = reqUrl.searchParams.get("url");
    if (!target) {
      send(res, 400, "Missing ?url=\n", { "Content-Type": "text/plain; charset=utf-8" }, req);
      return;
    }
    touchClient();

    // HLS playlists must be buffered so segment URLs can be rewritten through /proxy.
    // Media (VOD MP4, TS segments, etc.) is streamed — no full-body RAM buffer.
    if (!looksLikePlaylistUrl(target)) {
      const opId = beginOp("proxy", target);
      await upstreamGate.acquire();
      try {
        await streamProxyToClient(req, res, target);
        return;
      } catch (error) {
        if (error && error.code === "PLAYLIST_NEEDS_BUFFER") {
          console.log(`  ↳ stream→buffer playlist host=${sec.safeLogHost(target)}`);
          // Fall through to buffered rewrite path.
        } else if (error && error.code === "PANEL_REFUSE") {
          console.log(`  ↳ upstream refuse HTTP ${error.status} host=${sec.safeLogHost(target)}`);
          if (!res.headersSent) {
            send(
              res,
              502,
              `IPTV panel refused this stream (HTTP ${error.status}). Close VLC/other IPTV apps (many accounts allow only 1 connection), wait a few seconds, then retry — or Open in VLC.\n`,
              { "Content-Type": "text/plain; charset=utf-8" },
              req
            );
          }
          return;
        } else {
          console.log(`  ↳ ERROR ${error.message || error} host=${sec.safeLogHost(target)}`);
          if (!res.headersSent) {
            send(res, 502, `Proxy error: ${error.message || error}\n`, { "Content-Type": "text/plain; charset=utf-8" }, req);
          }
          return;
        }
      } finally {
        upstreamGate.release();
        endOp(opId);
      }
    }

    try {
      const up = await fetchUpstream(target);
      // Provider custom denies (common on Xtream): not real HTTP semantics.
      if (up.status === 458 || up.status === 884) {
        console.log(`  ↳ upstream refuse HTTP ${up.status} host=${sec.safeLogHost(target)}`);
        send(
          res,
          502,
          `IPTV panel refused this stream (HTTP ${up.status}). Close VLC/other IPTV apps (many accounts allow only 1 connection), wait a few seconds, then retry — or Open in VLC.\n`,
          { "Content-Type": "text/plain; charset=utf-8" },
          req
        );
        return;
      }
      const type = up.headers["content-type"] || "application/octet-stream";
      if (isPlaylist(type, up.body, up.finalUrl || target)) {
        const text = rewriteM3u8(up.body.toString("utf8"), up.finalUrl || target);
        console.log(`  ↳ playlist ${up.status} (${text.length} chars) host=${sec.safeLogHost(up.finalUrl || target)}`);
        send(
          res,
          up.status >= 400 ? up.status : 200,
          text,
          { "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8" },
          req
        );
        return;
      }
      console.log(`  ↳ binary ${up.status} ${up.body.length}b ${type} host=${sec.safeLogHost(up.finalUrl || target)}`);
      const imgHeaders = { "Content-Type": type };
      if (/^image\//i.test(type)) imgHeaders["Cache-Control"] = "public, max-age=86400";
      send(res, up.status, up.body, imgHeaders, req);
    } catch (error) {
      console.log(`  ↳ ERROR ${error.message || error} host=${sec.safeLogHost(target)}`);
      send(res, 502, `Proxy error: ${error.message || error}\n`, { "Content-Type": "text/plain; charset=utf-8" }, req);
    }
    return;
  }

  send(
    res,
    404,
    "NexusHub Desktop Engine — use /health /engine /activity /proxy /remux /remux/stop /probe /resolve /ping /quit /protocol/*\n",
    { "Content-Type": "text/plain; charset=utf-8" },
    req,
    { allowUnauthenticated: true }
  );
});

function alreadyRunning() {
  return new Promise((resolve) => {
    const req = http.get(`http://${HOST}:${PORT}/health`, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(800, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function main() {
  // Protocol URL launches (nexushub-engine://…) only start the server — never execute URL params.
  const protocolArgs = ARGV.filter(isProtocolLaunchArg);
  if (protocolArgs.length) {
    console.log(`Protocol launch ignored payload (start only): ${protocolArgs[0].slice(0, 64)}`);
  }

  if (hasCliFlag("diagnostics") || hasCliFlag("diagnose")) {
    printDiagnostics();
    return;
  }
  if (hasCliFlag("register-protocol")) {
    const result = registerProtocol();
    console.log(result.ok ? "Protocol registered." : `Register failed: ${result.error}`);
    process.exit(result.ok ? 0 : 1);
    return;
  }
  if (hasCliFlag("unregister-protocol")) {
    const result = unregisterProtocol();
    console.log(result.ok ? "Protocol unregistered." : `Unregister failed: ${result.error}`);
    process.exit(result.ok ? 0 : 1);
    return;
  }

  // Phase 3: do NOT auto-register protocol or hide UI on startup.
  if (await alreadyRunning()) {
    console.log(`NexusHub Desktop Engine already running on http://${HOST}:${PORT}/`);
    setTimeout(() => process.exit(0), 800);
    return;
  }

  assertSafeBindHost();
  hideConsoleWindow();
  startIdleWatchdog();

  server.listen(PORT, HOST, () => {
    console.log(`NexusHub Desktop Engine on http://${HOST}:${PORT}/`);
    console.log(`Allowed web origins: ${ALLOWED_ORIGINS.join(", ")}`);
    console.log(`Session auth: required on /proxy /remux /probe /resolve /logo (token via allowlisted /engine)`);
    console.log(`SSRF filter: on · max buffer ${sec.MAX_BUFFER_BYTES} · concurrency ${sec.MAX_CONCURRENT_UPSTREAM}`);
    console.log(
      `UI: console ${HIDE_CONSOLE ? "hidden" : "visible"} · tray ${ENABLE_TRAY ? "on" : "off"} · protocol ${isProtocolRegistered() ? "registered" : "not registered (opt-in)"}`
    );
    console.log(`Quits ~${Math.round(IDLE_MS / 1000)}s after NexusHub stops pinging (or set NEXUSHUB_ENGINE_STAY=1).`);
    console.log(`Tips: --diagnostics · --register-protocol · --unregister-protocol`);
    startTrayIcon();
  });
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
