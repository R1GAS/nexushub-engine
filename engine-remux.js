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
/**
 * The one active remux: { child, timer, host, startedAt }. `host` is hostname only (no query)
 * for Phase 4 visibility. A new /remux replaces it (channel switch / seek) instead of 429.
 */
let session = null;

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

/** Accept only a real `tool` / `tool.exe` binary path (no shell metacharacters / relative tricks). */
function sanitizeToolBinary(candidate, tool) {
  const raw = String(candidate || "").trim();
  if (!raw) return "";
  if (/[\r\n\0]/.test(raw)) return "";
  const resolved = path.resolve(raw);
  const base = path.basename(resolved).toLowerCase();
  if (base !== tool && base !== `${tool}.exe`) return "";
  try {
    if (!fs.existsSync(resolved)) return "";
    const st = fs.statSync(resolved);
    if (!st.isFile()) return "";
  } catch {
    return "";
  }
  return resolved;
}

function sanitizeFfmpegBinary(candidate) {
  return sanitizeToolBinary(candidate, "ffmpeg");
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

let ffprobePathCache = null;
let ffprobeOkCache = null;

function resolveFfprobePath() {
  if (ffprobePathCache) return ffprobePathCache;
  const name = process.platform === "win32" ? "ffprobe.exe" : "ffprobe";
  const candidates = [process.env.NEXUSHUB_FFPROBE];
  const ffmpeg = resolveFfmpegPath();
  // Gyan / winget / Homebrew all install ffprobe beside ffmpeg.
  if (path.isAbsolute(ffmpeg)) candidates.push(path.join(path.dirname(ffmpeg), name));
  for (const bundled of bundledFfmpegCandidates()) candidates.push(path.join(path.dirname(bundled), name));
  if (process.platform !== "win32") {
    candidates.push("/opt/homebrew/bin/ffprobe", "/usr/local/bin/ffprobe", "/usr/bin/ffprobe");
  }
  for (const candidate of candidates) {
    const ok = sanitizeToolBinary(candidate, "ffprobe");
    if (ok) {
      ffprobePathCache = ok;
      return ffprobePathCache;
    }
  }
  ffprobePathCache = name;
  return ffprobePathCache;
}

function isFfprobeAvailable() {
  if (ffprobeOkCache != null) return ffprobeOkCache;
  try {
    const result = spawnSync(resolveFfprobePath(), ["-version"], {
      windowsHide: true,
      shell: false,
      timeout: 4000,
      encoding: "utf8",
    });
    ffprobeOkCache = result.status === 0;
  } catch {
    ffprobeOkCache = false;
  }
  return ffprobeOkCache;
}

/** Minimal env for FFmpeg / ffprobe children — no Engine secrets or user env. */
function childEnv() {
  return {
    PATH: process.env.PATH || process.env.Path || "",
    Path: process.env.Path || process.env.PATH || "",
    SystemRoot: process.env.SystemRoot || "",
    WINDIR: process.env.WINDIR || "",
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
  };
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
  const probe = isFfprobeAvailable();
  return {
    remux: available,
    ffmpeg: available ? resolveFfmpegPath() : "",
    remuxPath: "/remux?url=",
    probe,
    ffprobe: probe ? resolveFfprobePath() : "",
    probePath: "/probe?url=",
    remuxBusy: Boolean(session),
    remuxHost: session ? session.host : "",
    remuxStartedAt: session ? session.startedAt : 0,
    remuxMaxMs: Number(process.env.NEXUSHUB_REMUX_MAX_MS || DEFAULT_REMUX_MAX_MS),
  };
}

const FFMPEG_PROTOCOLS = "http,https,tcp,tls,crypto";

/** Fixed templates only — never built from user query strings. */
function buildFfmpegArgs(targetUrl, { transcodeVideo = false, startSeconds = 0 } = {}) {
  const videoArgs = transcodeVideo
    ? ["-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p"]
    : ["-c:v", "copy"];
  return [
    "-hide_banner",
    "-loglevel",
    "error",
    "-nostdin",
    // FFmpeg fetches nested URLs itself (HLS segments, keys); never let them reach file:/pipe:/etc.
    "-protocol_whitelist",
    FFMPEG_PROTOCOLS,
    "-user_agent",
    process.env.NEXUSHUB_PROXY_UA || "VLC/3.0.20 LibVLC/3.0.20",
    // Input seek: output timestamps restart at 0, so the player adds `start` to currentTime.
    ...(startSeconds > 0 ? ["-ss", startSeconds.toFixed(3)] : []),
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

/** Kill one session's FFmpeg. Only clears `session` if it is still the active one. */
function stopSession(target, reason) {
  if (!target || target.stopped) return false;
  target.stopped = reason || "stop";
  if (target.timer) clearTimeout(target.timer);
  if (session === target) session = null;
  try {
    target.child.kill("SIGKILL");
  } catch {
    /* ignore */
  }
  if (reason) console.log(`  ↳ remux stopped (${reason})`);
  return true;
}

function stopRemux(reason = "stop") {
  return stopSession(session, reason);
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
  if (session) stopSession(session, "replaced");

  const transcodeVideo = Boolean(options && options.transcodeVideo);
  const startSeconds = Number((options && options.startSeconds) || 0);
  const bin = resolveFfmpegPath();
  const args = buildFfmpegArgs(targetUrl, { transcodeVideo, startSeconds });
  let started = false;
  let stderrBuf = "";
  let child;
  try {
    child = spawn(bin, args, {
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      cwd: os.tmpdir(),
      env: childEnv(),
    });
  } catch (error) {
    return { ok: false, status: 500, error: String((error && error.message) || error) };
  }

  const own = { child, timer: null, host: remuxHostOf(targetUrl), startedAt: Date.now(), stopped: false };
  session = own;
  const cleanup = (why) => stopSession(own, why || "cleanup");

  child.stderr.on("data", (chunk) => {
    stderrBuf += String(chunk || "");
    if (stderrBuf.length > 4000) stderrBuf = stderrBuf.slice(-4000);
  });

  child.on("error", (error) => {
    if (!started && !res.headersSent) {
      res.writeHead(500, {
        ...baseHeaders,
        "Content-Type": "text/plain; charset=utf-8",
      });
      res.end(`Remux failed to start: ${error.message || error}\n`);
    }
    cleanup("spawn-error");
  });

  child.on("close", (code) => {
    if (own.timer) clearTimeout(own.timer);
    if (session === own) session = null;
    if (!started && !res.headersSent && own.stopped === "replaced") {
      res.writeHead(409, { ...baseHeaders, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Remux replaced by a newer request\n");
    } else if (!started && !res.headersSent) {
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
  });

  res.on("close", () => {
    if (!res.writableEnded) cleanup("client-close");
  });

  child.stdout.once("data", (chunk) => {
    if (started) return;
    started = true;
    res.writeHead(200, {
      ...baseHeaders,
      "Content-Type": "video/mp4",
      "Cache-Control": "no-store",
    });
    res.write(chunk);
    child.stdout.pipe(res, { end: true });
  });

  const maxMs = Number(process.env.NEXUSHUB_REMUX_MAX_MS || DEFAULT_REMUX_MAX_MS);
  own.timer = setTimeout(() => cleanup("timeout"), maxMs);
  own.timer.unref?.();

  return { ok: true };
}

/** Longest seek offset accepted on /remux (seconds). */
const MAX_START_SECONDS = 24 * 60 * 60;

/**
 * Parse /remux query — only url + optional transcode|vcodec=h264 + start (+ token handled by caller).
 * Rejects unknown keys so users cannot smuggle FFmpeg flags via the query string.
 */
function parseRemuxQuery(searchParams) {
  const allowed = new Set(["url", "token", "transcode", "vcodec", "start"]);
  for (const key of searchParams.keys()) {
    if (!allowed.has(key)) {
      return { ok: false, status: 400, error: `Unknown remux parameter: ${key}` };
    }
  }
  const target = searchParams.get("url");
  if (!target) return { ok: false, status: 400, error: "Missing ?url=" };

  const vcodec = String(searchParams.get("vcodec") || "").trim().toLowerCase();
  if (vcodec && vcodec !== "h264") {
    return { ok: false, status: 400, error: "Only vcodec=h264 is supported" };
  }
  const transcodeVideo = searchParams.get("transcode") === "1" || vcodec === "h264";

  // Plain decimal seconds only — re-formatted with toFixed before it reaches FFmpeg.
  const rawStart = searchParams.get("start");
  let startSeconds = 0;
  if (rawStart != null && rawStart !== "") {
    if (!/^\d{1,6}(?:\.\d{1,3})?$/.test(rawStart) || Number(rawStart) > MAX_START_SECONDS) {
      return { ok: false, status: 400, error: `start must be seconds between 0 and ${MAX_START_SECONDS}` };
    }
    startSeconds = Number(rawStart);
  }
  return { ok: true, target, transcodeVideo, startSeconds };
}

/** Parse /probe query — only url (+ token handled by caller). */
function parseProbeQuery(searchParams) {
  for (const key of searchParams.keys()) {
    if (key !== "url" && key !== "token") {
      return { ok: false, status: 400, error: `Unknown probe parameter: ${key}` };
    }
  }
  const target = searchParams.get("url");
  if (!target) return { ok: false, status: 400, error: "Missing ?url=" };
  return { ok: true, target };
}

const PROBE_TIMEOUT_MS = Number(process.env.NEXUSHUB_PROBE_TIMEOUT_MS || 20000);
const PROBE_MAX_OUTPUT = 1024 * 1024;
const probeGate = sec.createConcurrencyGate(2);

/** Fixed ffprobe template — JSON summary of container + streams, nothing user-controlled but the URL. */
function buildFfprobeArgs(targetUrl) {
  return [
    "-hide_banner",
    "-v",
    "error",
    "-protocol_whitelist",
    FFMPEG_PROTOCOLS,
    "-user_agent",
    process.env.NEXUSHUB_PROXY_UA || "VLC/3.0.20 LibVLC/3.0.20",
    "-rw_timeout",
    "15000000",
    "-show_entries",
    "format=format_name,duration,bit_rate:" +
      "stream=index,codec_type,codec_name,profile,width,height,pix_fmt,channels,channel_layout,sample_rate:" +
      "stream_tags=language,title",
    "-of",
    "json",
    "-i",
    String(targetUrl),
  ];
}

function numOrNull(v) {
  const n = Number(v);
  return v != null && v !== "" && Number.isFinite(n) ? n : null;
}

/** Reduce ffprobe JSON to the facts the web app needs to pick direct play / remux / transcode. */
function summarizeProbe(raw) {
  const format = (raw && raw.format) || {};
  const streams = Array.isArray(raw && raw.streams) ? raw.streams : [];
  const tags = (s) => (s && s.tags) || {};
  const out = {
    container: String(format.format_name || ""),
    duration: numOrNull(format.duration),
    bitRate: numOrNull(format.bit_rate),
    video: [],
    audio: [],
    subtitles: [],
  };
  for (const s of streams) {
    const base = { index: s.index, codec: String(s.codec_name || "") };
    if (s.codec_type === "video") {
      out.video.push({
        ...base,
        profile: s.profile || "",
        width: numOrNull(s.width),
        height: numOrNull(s.height),
        pixFmt: s.pix_fmt || "",
      });
    } else if (s.codec_type === "audio") {
      out.audio.push({
        ...base,
        profile: s.profile || "",
        channels: numOrNull(s.channels),
        channelLayout: s.channel_layout || "",
        sampleRate: numOrNull(s.sample_rate),
        language: tags(s).language || "",
        title: tags(s).title || "",
      });
    } else if (s.codec_type === "subtitle") {
      out.subtitles.push({ ...base, language: tags(s).language || "", title: tags(s).title || "" });
    }
  }
  return out;
}

/**
 * Run ffprobe against one upstream URL. Caller must have already checked auth/CORS.
 * @returns {Promise<{ ok: true, info: object } | { ok: false, status: number, error: string }>}
 */
async function probeMedia(targetUrl) {
  try {
    await sec.assertSafeUpstreamUrl(targetUrl);
  } catch (error) {
    return { ok: false, status: 403, error: String((error && error.message) || error || "Blocked destination") };
  }
  if (!isFfprobeAvailable()) {
    return {
      ok: false,
      status: 503,
      error: "ffprobe not found. Install it beside ffmpeg, or set NEXUSHUB_FFPROBE to the ffprobe binary.",
    };
  }

  await probeGate.acquire();
  try {
    return await new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };
      let child;
      try {
        child = spawn(resolveFfprobePath(), buildFfprobeArgs(targetUrl), {
          windowsHide: true,
          shell: false,
          stdio: ["ignore", "pipe", "pipe"],
          cwd: os.tmpdir(),
          env: childEnv(),
        });
      } catch (error) {
        resolve({ ok: false, status: 500, error: String((error && error.message) || error) });
        return;
      }
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish({ ok: false, status: 504, error: "Probe timed out" });
      }, PROBE_TIMEOUT_MS);
      timer.unref?.();

      child.stdout.on("data", (chunk) => {
        stdout += String(chunk || "");
        if (stdout.length > PROBE_MAX_OUTPUT) {
          child.kill("SIGKILL");
          finish({ ok: false, status: 502, error: "Probe output too large" });
        }
      });
      child.stderr.on("data", (chunk) => {
        stderr += String(chunk || "");
        if (stderr.length > 4000) stderr = stderr.slice(-4000);
      });
      child.on("error", (error) => finish({ ok: false, status: 500, error: String(error.message || error) }));
      child.on("close", (code) => {
        if (code !== 0) {
          finish({ ok: false, status: 502, error: stderr.trim() || `ffprobe exited with code ${code}` });
          return;
        }
        try {
          finish({ ok: true, info: summarizeProbe(JSON.parse(stdout)) });
        } catch {
          finish({ ok: false, status: 502, error: "Unreadable ffprobe output" });
        }
      });
    });
  } finally {
    probeGate.release();
  }
}

module.exports = {
  resolveFfmpegPath,
  isFfmpegAvailable,
  resolveFfprobePath,
  isFfprobeAvailable,
  getRemuxCapabilities,
  startRemuxStream,
  stopRemux,
  parseRemuxQuery,
  parseProbeQuery,
  buildFfmpegArgs,
  buildFfprobeArgs,
  summarizeProbe,
  probeMedia,
  sanitizeFfmpegBinary,
};
