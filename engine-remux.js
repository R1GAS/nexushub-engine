/**
 * Desktop Engine VOD remux (system FFmpeg) — Phase 2 hardened.
 * Fixed arg templates only; http(s) input validated via engine-security;
 * no shell; kill on shutdown; no arbitrary user FFmpeg flags.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn, spawnSync } = require("child_process");
const sec = require("./engine-security");

let ffmpegPathCache = null;
let ffmpegOkCache = null;
let remuxChild = null;
let remuxTimer = null;
/** Hostname only (no query) of the active remux upstream — for Phase 4 visibility. */
let remuxHost = "";
let remuxStartedAt = 0;

/** Default 2h (was 6h) — long enough for VOD, not unbounded. */
const DEFAULT_REMUX_MAX_MS = 2 * 60 * 60 * 1000;

function walkFindFfmpeg(dir, depth) {
  if (!dir || depth < 0) return "";
  try {
    if (!fs.existsSync(dir)) return "";
    const direct = path.join(dir, "ffmpeg.exe");
    if (fs.existsSync(direct)) return direct;
    const bin = path.join(dir, "bin", "ffmpeg.exe");
    if (fs.existsSync(bin)) return bin;
    if (depth === 0) return "";
    for (const name of fs.readdirSync(dir)) {
      if (/^ffmpeg/i.test(name) || /full_build|essentials/i.test(name) || name === "bin") {
        const hit = walkFindFfmpeg(path.join(dir, name), depth - 1);
        if (hit) return hit;
      }
    }
  } catch {
    /* ignore */
  }
  return "";
}

/** Accept only a real ffmpeg binary path (no shell metacharacters / relative tricks). */
function sanitizeFfmpegBinary(candidate) {
  const raw = String(candidate || "").trim();
  if (!raw) return "";
  if (/[\r\n\0]/.test(raw)) return "";
  const resolved = path.resolve(raw);
  const base = path.basename(resolved).toLowerCase();
  if (base !== "ffmpeg" && base !== "ffmpeg.exe") return "";
  try {
    if (!fs.existsSync(resolved)) return "";
    const st = fs.statSync(resolved);
    if (!st.isFile()) return "";
  } catch {
    return "";
  }
  return resolved;
}

/** FFmpeg shipped next to the Engine .exe (release zip) or in the repo vendor cache (dev). */
function bundledFfmpegCandidates() {
  const win = process.platform === "win32";
  const name = win ? "ffmpeg.exe" : "ffmpeg";
  const dirs = [];
  try {
    // Packaged Engine: ffmpeg.exe sits beside NexusHub-Desktop-Engine.exe after unzip.
    dirs.push(path.dirname(process.execPath));
  } catch {
    /* ignore */
  }
  try {
    // Dev / unpackaged: vendor/ffmpeg-win64 from scripts/fetch-engine-ffmpeg.js
    dirs.push(path.join(__dirname, "vendor", "ffmpeg-win64"));
    dirs.push(path.join(__dirname, "..", "vendor", "ffmpeg-win64"));
  } catch {
    /* ignore */
  }
  try {
    const local = process.env.LOCALAPPDATA || "";
    if (local) dirs.push(path.join(local, "NexusHub", "ffmpeg"));
  } catch {
    /* ignore */
  }
  return dirs.map((dir) => path.join(dir, name));
}

function resolveFfmpegPath() {
  if (ffmpegPathCache) return ffmpegPathCache;

  const fromEnv = sanitizeFfmpegBinary(process.env.NEXUSHUB_FFMPEG);
  if (fromEnv) {
    ffmpegPathCache = fromEnv;
    return ffmpegPathCache;
  }

  // Prefer the copy we ship with the Engine zip (no separate install required).
  for (const candidate of bundledFfmpegCandidates()) {
    const ok = sanitizeFfmpegBinary(candidate);
    if (ok) {
      ffmpegPathCache = ok;
      return ffmpegPathCache;
    }
  }

  const win = process.platform === "win32";
  if (!win) {
    const unix = ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/usr/bin/ffmpeg"];
    for (const candidate of unix) {
      const ok = sanitizeFfmpegBinary(candidate);
      if (ok) {
        ffmpegPathCache = ok;
        return ffmpegPathCache;
      }
    }
    ffmpegPathCache = "ffmpeg";
    return ffmpegPathCache;
  }

  const local = process.env.LOCALAPPDATA || "";
  const candidates = [
    path.join(local, "Microsoft", "WinGet", "Links", "ffmpeg.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "ffmpeg", "bin", "ffmpeg.exe"),
    path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "ffmpeg", "bin", "ffmpeg.exe"),
    "C:\\ffmpeg\\bin\\ffmpeg.exe",
  ];

  const wingetPkg = walkFindFfmpeg(path.join(local, "Microsoft", "WinGet", "Packages"), 3);
  if (wingetPkg) candidates.unshift(wingetPkg);

  // Prefer where.exe over PowerShell Path probes (Phase 2: less PowerShell).
  try {
    const where = spawnSync("where.exe", ["ffmpeg"], {
      windowsHide: true,
      shell: false,
      timeout: 4000,
      encoding: "utf8",
    });
    if (where.status === 0) {
      const line = String(where.stdout || "")
        .split(/\r?\n/)
        .map((s) => s.trim())
        .find((s) => s && /\.exe$/i.test(s));
      if (line) candidates.unshift(line);
    }
  } catch {
    /* ignore */
  }

  for (const candidate of candidates) {
    const ok = sanitizeFfmpegBinary(candidate);
    if (ok) {
      ffmpegPathCache = ok;
      return ffmpegPathCache;
    }
  }
  ffmpegPathCache = "ffmpeg.exe";
  return ffmpegPathCache;
}

function isFfmpegAvailable() {
  if (ffmpegOkCache != null) return ffmpegOkCache;
  try {
    const bin = resolveFfmpegPath();
    const result = spawnSync(bin, ["-version"], {
      windowsHide: true,
      shell: false,
      timeout: 4000,
      encoding: "utf8",
    });
    ffmpegOkCache = result.status === 0;
  } catch {
    ffmpegOkCache = false;
  }
  return ffmpegOkCache;
}

function remuxHostOf(url) {
  try {
    return new URL(String(url || "")).host || "";
  } catch {
    return "";
  }
}

function getRemuxCapabilities() {
  const available = isFfmpegAvailable();
  return {
    remux: available,
    ffmpeg: available ? resolveFfmpegPath() : "",
    remuxPath: "/remux?url=",
    remuxBusy: Boolean(remuxChild),
    remuxHost: remuxChild ? remuxHost : "",
    remuxStartedAt: remuxChild ? remuxStartedAt : 0,
    remuxMaxMs: Number(process.env.NEXUSHUB_REMUX_MAX_MS || DEFAULT_REMUX_MAX_MS),
  };
}

/** Decode/encode threads. Unset uses 2 so one playback cannot occupy every core. */
function ffmpegThreadCount() {
  const raw = Number(process.env.NEXUSHUB_FFMPEG_THREADS);
  if (Number.isInteger(raw) && raw >= 1 && raw <= 8) return String(raw);
  return "2";
}

function deprioritizeRemux(child) {
  const pid = child && child.pid;
  const below = os.constants && os.constants.priority && os.constants.priority.PRIORITY_BELOW_NORMAL;
  if (!pid || below == null || typeof os.setPriority !== "function") return;
  try {
    os.setPriority(pid, below);
  } catch {
    /* priority is best-effort */
  }
}

/** Fixed templates only — never built from user query strings. */
function buildFfmpegArgs(targetUrl, { transcodeVideo = false } = {}) {
  const threads = ffmpegThreadCount();
  const videoArgs = transcodeVideo
    ? ["-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-crf", "23", "-pix_fmt", "yuv420p", "-threads", threads]
    : ["-c:v", "copy"];
  return [
    "-hide_banner",
    "-loglevel",
    "error",
    "-nostdin",
    "-threads",
    threads,
    "-user_agent",
    process.env.NEXUSHUB_PROXY_UA || "VLC/3.0.20 LibVLC/3.0.20",
    "-i",
    String(targetUrl),
    "-map",
    "0:v:0",
    "-map",
    "0:a:0?",
    ...videoArgs,
    "-c:a",
    "aac",
    "-ac",
    "2",
    "-b:a",
    "192k",
    "-sn",
    "-dn",
    "-movflags",
    "frag_keyframe+empty_moov+default_base_moof",
    "-f",
    "mp4",
    "pipe:1",
  ];
}

function stopRemux(reason = "stop") {
  if (remuxTimer) {
    try {
      clearTimeout(remuxTimer);
    } catch {
      /* ignore */
    }
    remuxTimer = null;
  }
  if (!remuxChild) {
    remuxHost = "";
    remuxStartedAt = 0;
    return false;
  }
  const child = remuxChild;
  remuxChild = null;
  remuxHost = "";
  remuxStartedAt = 0;
  try {
    child.kill("SIGKILL");
  } catch {
    /* ignore */
  }
  if (reason) console.log(`  ↳ remux stopped (${reason})`);
  return true;
}

/**
 * Pipe a remuxed fMP4 stream to `res`. Caller must have already checked auth/CORS.
 * Upstream URL is SSRF-checked here again (defense in depth).
 * @returns {Promise<{ ok: true } | { ok: false, status: number, error: string }>}
 */
async function startRemuxStream(targetUrl, res, baseHeaders = {}, options = {}) {
  try {
    await sec.assertSafeUpstreamUrl(targetUrl);
  } catch (error) {
    return { ok: false, status: 403, error: String((error && error.message) || error || "Blocked destination") };
  }

  if (!isFfmpegAvailable()) {
    return {
      ok: false,
      status: 503,
      error: "FFmpeg not found. Install FFmpeg and ensure it is on PATH, or set NEXUSHUB_FFMPEG to the ffmpeg binary.",
    };
  }
  if (remuxChild) {
    return { ok: false, status: 429, error: "Another remux is already running. Try again in a moment." };
  }

  const transcodeVideo = Boolean(options && options.transcodeVideo);
  const bin = resolveFfmpegPath();
  const args = buildFfmpegArgs(targetUrl, { transcodeVideo });
  remuxHost = remuxHostOf(targetUrl);
  remuxStartedAt = Date.now();

  let started = false;
  let stderrBuf = "";
  try {
    remuxChild = spawn(bin, args, {
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      cwd: os.tmpdir(),
      env: {
        PATH: process.env.PATH || process.env.Path || "",
        Path: process.env.Path || process.env.PATH || "",
        SystemRoot: process.env.SystemRoot || "",
        WINDIR: process.env.WINDIR || "",
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
      },
    });
  } catch (error) {
    remuxChild = null;
    remuxHost = "";
    remuxStartedAt = 0;
    return { ok: false, status: 500, error: String((error && error.message) || error) };
  }

  deprioritizeRemux(remuxChild);
  const cleanup = (why) => stopRemux(why || "cleanup");

  remuxChild.stderr.on("data", (chunk) => {
    stderrBuf += String(chunk || "");
    if (stderrBuf.length > 4000) stderrBuf = stderrBuf.slice(-4000);
  });

  remuxChild.on("error", (error) => {
    if (!started && !res.headersSent) {
      res.writeHead(500, {
        ...baseHeaders,
        "Content-Type": "text/plain; charset=utf-8",
      });
      res.end(`Remux failed to start: ${error.message || error}\n`);
    }
    cleanup("spawn-error");
  });

  remuxChild.on("close", (code) => {
    if (remuxTimer) {
      clearTimeout(remuxTimer);
      remuxTimer = null;
    }
    if (!started && !res.headersSent) {
      const hint = stderrBuf.trim() || `ffmpeg exited with code ${code}`;
      res.writeHead(502, {
        ...baseHeaders,
        "Content-Type": "text/plain; charset=utf-8",
      });
      res.end(`Remux failed: ${hint}\n`);
    } else if (!res.writableEnded) {
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }
    remuxChild = null;
    remuxHost = "";
    remuxStartedAt = 0;
  });

  res.on("close", () => {
    if (!res.writableEnded) cleanup("client-close");
  });

  remuxChild.stdout.once("data", (chunk) => {
    if (started) return;
    started = true;
    res.writeHead(200, {
      ...baseHeaders,
      "Content-Type": "video/mp4",
      "Cache-Control": "no-store",
    });
    res.write(chunk);
    remuxChild.stdout.pipe(res, { end: true });
  });

  const maxMs = Number(process.env.NEXUSHUB_REMUX_MAX_MS || DEFAULT_REMUX_MAX_MS);
  remuxTimer = setTimeout(() => cleanup("timeout"), maxMs);
  remuxTimer.unref?.();

  return { ok: true };
}

/**
 * Parse /remux query — only url + optional transcode|vcodec=h264 (+ token handled by caller).
 * Rejects unknown keys so users cannot smuggle FFmpeg flags via the query string.
 */
function parseRemuxQuery(searchParams) {
  const allowed = new Set(["url", "token", "transcode", "vcodec"]);
  for (const key of searchParams.keys()) {
    if (!allowed.has(key)) {
      return { ok: false, status: 400, error: `Unknown remux parameter: ${key}` };
    }
  }
  const target = searchParams.get("url");
  if (!target) return { ok: false, status: 400, error: "Missing ?url=" };
  if (/\.m3u8?(?:\?|#|$)/i.test(String(target))) {
    return { ok: false, status: 415, error: "HLS playlists are not remuxed" };
  }

  const vcodec = String(searchParams.get("vcodec") || "").trim().toLowerCase();
  if (vcodec && vcodec !== "h264") {
    return { ok: false, status: 400, error: "Only vcodec=h264 is supported" };
  }
  const transcodeVideo = searchParams.get("transcode") === "1" || vcodec === "h264";
  return { ok: true, target, transcodeVideo };
}

module.exports = {
  resolveFfmpegPath,
  isFfmpegAvailable,
  getRemuxCapabilities,
  startRemuxStream,
  stopRemux,
  parseRemuxQuery,
  buildFfmpegArgs,
  sanitizeFfmpegBinary,
};
